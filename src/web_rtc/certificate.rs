//! Persistent DTLS identity: serialized initialization and atomic private writes.

use crate::error::{Error, Result};
use fs2::FileExt;
use saorsa_transport::webrtc_direct::WebRtcCertificate;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

pub(super) async fn load_or_generate_certificate(path: &Path) -> Result<WebRtcCertificate> {
    let path = path.to_owned();
    // File locking and fsync must not block a Tokio worker. Cancellation of
    // startup must also not interrupt publication halfway through a write.
    tokio::task::spawn_blocking(move || load_or_generate(&path))
        .await
        .map_err(|error| Error::Startup(format!("WebRTC certificate task failed: {error}")))?
}

fn load_or_generate(path: &Path) -> Result<WebRtcCertificate> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    // Keep the lock file: unlinking it could let another initializer lock a
    // different inode while this one is still in use. Closing releases the lock.
    let lock = private_options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock_exclusive()?;

    match private_options().open(path) {
        Ok(mut file) => {
            restrict_permissions(&file)?;
            let mut pem = String::new();
            file.read_to_string(&mut pem)?;
            // Never regenerate a corrupt existing identity silently.
            WebRtcCertificate::from_pem(&pem).map_err(|error| {
                Error::Startup(format!(
                    "failed to load WebRTC certificate {}: {error}",
                    path.display()
                ))
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let certificate = WebRtcCertificate::generate().map_err(|error| {
                Error::Startup(format!("failed to generate WebRTC certificate: {error}"))
            })?;
            // NamedTempFile is created with mode 0600 on Unix, before any key
            // bytes are written. Other platforms inherit the directory ACL.
            let mut temp = tempfile::NamedTempFile::new_in(parent)?;
            restrict_permissions(temp.as_file())?;
            temp.write_all(certificate.serialize_pem().as_bytes())?;
            temp.as_file().sync_all()?;
            let installed = temp.persist(path).map_err(|error| {
                Error::Startup(format!(
                    "failed to install WebRTC certificate {}: {error}",
                    path.display()
                ))
            })?;
            installed.sync_all()?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
            Ok(certificate)
        }
        Err(error) => Err(error.into()),
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn restrict_permissions(file: &File) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "WebRTC certificate must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            file.sync_all()?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn certificate_is_created_private_and_existing_permissions_are_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webrtc.pem");
        let first = load_or_generate_certificate(&path)
            .await
            .unwrap()
            .sha256_digest()
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let second = load_or_generate_certificate(&path)
            .await
            .unwrap()
            .sha256_digest()
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[tokio::test]
    async fn concurrent_initializers_load_the_same_persisted_identity() {
        let directory = tempfile::tempdir().unwrap();
        for attempt in 0..8 {
            let path = directory.path().join(format!("webrtc-{attempt}.pem"));
            let (first, second) = tokio::join!(
                load_or_generate_certificate(&path),
                load_or_generate_certificate(&path)
            );
            let digest = first.unwrap().sha256_digest().unwrap();
            assert_eq!(digest, second.unwrap().sha256_digest().unwrap());
            assert_eq!(
                digest,
                load_or_generate_certificate(&path)
                    .await
                    .unwrap()
                    .sha256_digest()
                    .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn interrupted_temp_write_leaves_the_existing_identity_intact() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("webrtc.pem");
        let first = load_or_generate_certificate(&path)
            .await
            .unwrap()
            .sha256_digest()
            .unwrap();
        let mut orphan = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        orphan.write_all(b"incomplete private key").unwrap();
        // An incomplete temporary file is never the published certificate.
        assert_eq!(
            first,
            load_or_generate_certificate(&path)
                .await
                .unwrap()
                .sha256_digest()
                .unwrap()
        );
        std::fs::write(&path, b"truncated PEM").unwrap();
        assert!(matches!(
            load_or_generate_certificate(&path).await,
            Err(Error::Startup(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"truncated PEM");
    }
}
