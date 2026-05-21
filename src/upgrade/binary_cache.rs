//! Disk cache for downloaded upgrade archives.
//!
//! When multiple ant-node instances detect the same upgrade, only the first
//! one needs to download the archive. `BinaryCache` stores the **signed
//! archive together with its detached ML-DSA-65 signature** so that
//! subsequent nodes can reuse it.
//!
//! ## Security model
//!
//! The ML-DSA-65 signature is the security gate, and it covers the *archive*
//! bytes — not the extracted binary. A previous version cached the extracted
//! binary and, on a cache hit, returned it after only a SHA-256 check against
//! a sibling metadata file. SHA-256 is not a security control: anyone able to
//! write to the shared cache directory (a co-located process, a shared
//! container volume, a low-privilege foothold) could replace the cached
//! binary and its `.meta.json` with a matching hash, and the next node would
//! execute it **without any signature verification** — persistent RCE.
//!
//! This module now caches the *archive + signature* and, on **every** cache
//! hit, re-runs ML-DSA-65 verification over the cached archive before it is
//! used. A tampered archive fails verification (the release key is pinned in
//! the binary and cannot be forged); a tampered or missing signature fails
//! likewise. The extracted binary is always derived fresh from the
//! just-verified archive by the caller, so a poisoned cache entry can never
//! be executed. The SHA-256 metadata is retained only as a fast corruption
//! pre-check, never as the trust decision.
//!
//! ## Residual: cache entries are not bound to a specific release version
//!
//! `signature::SIGNING_CONTEXT = "ant-node-release-v1"` is constant across
//! versions, so the ML-DSA signature attests to "this archive is a valid
//! ant-node release", not "this archive is release X.Y.Z". An attacker with
//! cache-dir write access who possesses any past validly-signed release can
//! plant it under a newer version's cache key; the next node performing
//! that upgrade accepts it and runs it as the newer version. Net effect:
//! forced downgrade or wrong-arch crash loop, not arbitrary RCE.
//!
//! This is out of scope of the cache-poisoning RCE class this module
//! addresses (which trusted SHA-256 alone on cache hits): the `cache_dir`
//! is `0o700` (defence in depth, see `cache_dir.rs`) and the attacker
//! already needs same-UID write to exploit this — they can replace the
//! running binary directly. Closing the gap properly requires upstream
//! release-signing changes (the signing context must include the version
//! string, e.g. `b"ant-node-release-v1:1.2.3"`) and is tracked as a
//! follow-up.

use crate::error::{Error, Result};
use crate::logging::{debug, warn};
use crate::upgrade::signature;
use fs2::FileExt;
use saorsa_pqc::api::sig::MlDsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Maximum size accepted for the `.meta.json` sidecar.
///
/// A well-formed `CachedArchiveMeta` serialises to roughly 120 bytes; the
/// 4 KiB cap is comfortably above any legitimate payload and tight enough
/// that an attacker who plants a metadata file the size of `/dev/zero`
/// cannot stall the metadata read into a hang or OOM.
const MAX_META_BYTES: u64 = 4 * 1024;

/// On-disk cache for downloaded, signature-verified upgrade archives.
#[derive(Clone)]
pub struct BinaryCache {
    /// Directory that holds cached archives, signatures, and metadata.
    cache_dir: PathBuf,
    /// Verification key override. `None` in production → the pinned release
    /// key embedded in [`signature`] is used (the real, unforgeable gate).
    /// Only ever `Some` via the `#[cfg(test)]` constructor, so test builds
    /// can exercise the cache with a generated keypair without weakening the
    /// production trust anchor in any way.
    verify_key: Option<MlDsaPublicKey>,
}

/// Metadata written alongside each cached archive.
///
/// The SHA-256 here is a fast integrity/corruption pre-check only. It is
/// **not** a security control: the ML-DSA-65 signature over the archive is
/// re-verified on every cache hit regardless of this value.
#[derive(Serialize, Deserialize)]
struct CachedArchiveMeta {
    /// Semantic version string (e.g. "1.2.3").
    version: String,
    /// Hex-encoded SHA-256 digest of the cached archive (corruption check).
    archive_sha256: String,
    /// When the archive was cached (seconds since UNIX epoch).
    cached_at_epoch_secs: u64,
}

impl BinaryCache {
    /// Create a new binary cache backed by the given directory.
    ///
    /// Production constructor: the cache verifies cached archives against the
    /// pinned release public key embedded in the binary.
    #[must_use]
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            verify_key: None,
        }
    }

    /// Test-only constructor that verifies against an explicit public key
    /// instead of the pinned release key (the production trust anchor is
    /// unchanged; this only exists so unit tests can produce verifiable
    /// signatures with a generated keypair).
    #[cfg(test)]
    #[must_use]
    pub fn new_with_verify_key(cache_dir: PathBuf, verify_key: MlDsaPublicKey) -> Self {
        Self {
            cache_dir,
            verify_key: Some(verify_key),
        }
    }

    /// Path of the cached archive for `version`.
    #[must_use]
    pub fn cached_archive_path(&self, version: &str) -> PathBuf {
        self.cache_dir.join(format!("ant-node-{version}.archive"))
    }

    /// Path of the cached detached signature for `version`.
    #[must_use]
    fn cached_signature_path(&self, version: &str) -> PathBuf {
        self.cache_dir.join(format!("ant-node-{version}.sig"))
    }

    /// Verify `archive` against `sig` using the pinned release key in
    /// production, or the injected test key under `#[cfg(test)]`.
    fn verify_archive(&self, archive: &Path, sig: &Path) -> Result<()> {
        self.verify_key.as_ref().map_or_else(
            || signature::verify_from_file(archive, sig),
            |key| signature::verify_from_file_with_key(archive, sig, key),
        )
    }

    /// Copy the cached archive into the caller-private `private_dir`,
    /// **cryptographically re-verify that private copy**, and return its
    /// path — or `None` if there is no usable, trusted cache entry.
    ///
    /// On every call this:
    /// 1. loads the sibling metadata and checks the version matches,
    /// 2. copies the cached archive + signature into `private_dir` (a
    ///    location only this process writes, e.g. the per-upgrade temp dir),
    /// 3. SHA-256 pre-checks the private copy against the metadata (fast
    ///    corruption check), then
    /// 4. **re-verifies the ML-DSA-65 signature over the private copy** with
    ///    the pinned release key — the actual security gate.
    ///
    /// Verifying the *private copy* (not the shared cache file) closes the
    /// TOCTOU window: an attacker with write access to the shared cache dir
    /// cannot swap the bytes between verification and extraction, because the
    /// caller extracts from the returned private path, which is the exact
    /// byte sequence that was verified and is unreachable to the attacker.
    ///
    /// Any failure (missing/corrupt metadata, copy error, hash mismatch,
    /// missing signature, or — critically — a signature that does not verify
    /// against the pinned release key) returns `None`, forcing a fresh,
    /// fully verified download.
    ///
    /// The caller MUST extract the binary from the returned (private) archive
    /// path, so the executed bytes always derive from signature-verified
    /// input that no other principal could have modified post-verification.
    // The verifier-side cache-hit gate is read top-to-bottom by anyone
    // auditing the security model. Splitting it into smaller helpers just
    // to placate clippy's line limit would scatter the threat model across
    // call sites without improving safety.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn get_verified_archive(&self, version: &str, private_dir: &Path) -> Option<PathBuf> {
        let cached_archive = self.cached_archive_path(version);
        let cached_sig = self.cached_signature_path(version);
        let meta_path = self.meta_path(version);

        // Read the metadata sidecar with a small, opened-handle size cap so
        // an attacker with cache-dir write cannot plant `meta.json` as a
        // symlink to `/dev/zero` (or any large/special file) and force a
        // hang/OOM here before the archive/sig hardening runs.
        let meta_data = {
            let (mut meta_file, meta_len) = match open_regular_capped(&meta_path, MAX_META_BYTES) {
                Ok(pair) => pair,
                Err(e) => {
                    debug!("Rejecting cache metadata for {version}: {e}");
                    return None;
                }
            };
            // `meta_len` is capped at MAX_META_BYTES (4 KiB), so this
            // truncation can never happen in practice; saturating_cast
            // makes that explicit for clippy on 32-bit targets.
            let cap = usize::try_from(meta_len).unwrap_or(usize::MAX);
            let mut buf = String::with_capacity(cap);
            if let Err(e) = meta_file.read_to_string(&mut buf) {
                debug!("Failed to read cache metadata for {version}: {e}");
                return None;
            }
            buf
        };
        let meta: CachedArchiveMeta = serde_json::from_str(&meta_data).ok()?;

        if meta.version != version {
            debug!("Binary cache version mismatch in metadata");
            return None;
        }

        // Open archive + signature ONCE each with size and file-type
        // validation on the opened handles. Subsequent reads / hash /
        // signature verification all go through the FDs opened here — there
        // is no second path-based stat or open after this point, so an
        // attacker who races a swap on the cache-dir paths (symlink, FIFO,
        // device, oversized file) after these validations cannot redirect
        // what gets staged into the private dir.
        //
        // Memory pressure note: `signature::verify_from_file*` reads the
        // archive into memory in full (it is the FIPS-204 verifier's
        // contract — message must be provided as a slice). `sha256_file`
        // streams in 8 KiB chunks and is not an OOM vector. The
        // `MAX_ARCHIVE_SIZE_BYTES` cap bounds the in-memory load and the
        // staging-dir disk footprint together.
        let (mut archive_file, archive_len) = match open_regular_capped(
            &cached_archive,
            crate::upgrade::apply::MAX_ARCHIVE_SIZE_BYTES as u64,
        ) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("Rejecting cached archive for {version}: {e}");
                return None;
            }
        };
        let (mut sig_file, sig_len) =
            match open_regular_capped(&cached_sig, signature::SIGNATURE_SIZE as u64) {
                Ok(pair) => pair,
                Err(e) => {
                    warn!("Rejecting cached signature for {version}: {e}");
                    return None;
                }
            };
        if sig_len != signature::SIGNATURE_SIZE as u64 {
            // open_regular_capped enforces ≤ max; we additionally require
            // EXACTLY SIGNATURE_SIZE (a shorter sig is not valid ML-DSA-65).
            warn!(
                "Cached signature for {version} has wrong size ({sig_len} bytes, \
                 expected {})",
                signature::SIGNATURE_SIZE
            );
            return None;
        }

        // Stream the validated archive + signature into the caller-private
        // directory FROM THE ALREADY-OPEN HANDLES (not from the path), so
        // the bytes the verifier reads are the exact bytes the open-handle
        // metadata checks were performed against. `take()` is belt-and-
        // braces against an attacker who extends the file after open.
        let private_archive = private_dir.join(format!("cached-{version}.archive"));
        let private_sig = private_dir.join(format!("cached-{version}.sig"));

        let cleanup = |reason: &str| {
            debug!("Cleaning staged cache copy for {version}: {reason}");
            let _ = fs::remove_file(&private_archive);
            let _ = fs::remove_file(&private_sig);
        };

        if let Err(e) = (|| -> io::Result<()> {
            let mut dest = File::create(&private_archive)?;
            io::copy(&mut (&mut archive_file).take(archive_len), &mut dest)?;
            Ok(())
        })() {
            debug!("Could not stage cached archive for {version}: {e}");
            cleanup("archive copy failed");
            return None;
        }
        if let Err(e) = (|| -> io::Result<()> {
            let mut dest = File::create(&private_sig)?;
            io::copy(&mut (&mut sig_file).take(sig_len), &mut dest)?;
            Ok(())
        })() {
            debug!("Could not stage cached signature for {version}: {e}");
            cleanup("signature copy failed");
            return None;
        }

        // Fast corruption pre-check on the PRIVATE copy (NOT the security
        // decision). A copy error or truncation surfaces here.
        let actual_hash = match sha256_file(&private_archive) {
            Ok(h) => h,
            Err(e) => {
                cleanup(&format!("sha256 read failed: {e}"));
                return None;
            }
        };
        if actual_hash != meta.archive_sha256 {
            warn!(
                "Binary cache SHA-256 mismatch for version {version} \
                 (expected {}, got {actual_hash}) — ignoring cache entry",
                meta.archive_sha256
            );
            cleanup("sha256 mismatch");
            return None;
        }

        // THE SECURITY GATE: re-verify the ML-DSA-65 signature over the
        // PRIVATE archive copy on every hit. The returned path is this same
        // private copy, so the caller extracts exactly the bytes that were
        // verified — a cache entry tampered with on disk (binary/archive
        // swap, forged metadata, or a post-verify swap attempt) cannot
        // produce a private copy whose signature verifies against the
        // pinned release key.
        if let Err(e) = self.verify_archive(&private_archive, &private_sig) {
            warn!(
                "Cached archive for version {version} FAILED ML-DSA signature \
                 re-verification ({e}); discarding cache entry (possible \
                 on-disk tampering). A fresh verified download will run."
            );
            cleanup("signature re-verification failed");
            return None;
        }

        debug!("Cached archive for version {version} passed ML-DSA re-verification");
        Some(private_archive)
    }

    /// Store a signature-verified archive in the cache.
    ///
    /// Both files are persisted (via write-to-temp-then-rename so readers
    /// never observe partial writes); the metadata file is written last so
    /// [`get_verified_archive`](Self::get_verified_archive) only succeeds
    /// once every file is complete.
    ///
    /// Defence in depth: this re-verifies the archive against its signature
    /// before caching, so a poisoned entry cannot be created through the
    /// supported path even if a caller forgot to verify first.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature does not verify, the inputs cannot
    /// be read, or the cache files cannot be written.
    pub fn store_archive(
        &self,
        version: &str,
        archive_path: &Path,
        signature_path: &Path,
    ) -> Result<()> {
        // Defence in depth: refuse to persist a non-regular file, an
        // oversize archive, or a misshapen signature — mirroring the
        // `get_verified_archive` cache-hit policy. `symlink_metadata`
        // refuses to chase a symlink the caller may have planted.
        let archive_meta = fs::symlink_metadata(archive_path)?;
        if !archive_meta.file_type().is_file() {
            return Err(Error::Upgrade(format!(
                "Refusing to cache archive for {version}: source is not a \
                 regular file (symlink/special)"
            )));
        }
        let archive_len = archive_meta.len();
        if archive_len > crate::upgrade::apply::MAX_ARCHIVE_SIZE_BYTES as u64 {
            return Err(Error::Upgrade(format!(
                "Refusing to cache archive for {version}: size {archive_len} bytes \
                 exceeds MAX_ARCHIVE_SIZE_BYTES"
            )));
        }
        let sig_meta = fs::symlink_metadata(signature_path)?;
        if !sig_meta.file_type().is_file() {
            return Err(Error::Upgrade(format!(
                "Refusing to cache archive for {version}: signature is not a \
                 regular file (symlink/special)"
            )));
        }
        let sig_len = sig_meta.len();
        if sig_len != signature::SIGNATURE_SIZE as u64 {
            return Err(Error::Upgrade(format!(
                "Refusing to cache archive for {version}: signature size {sig_len} \
                 bytes, expected {}",
                signature::SIGNATURE_SIZE
            )));
        }

        self.verify_archive(archive_path, signature_path)
            .map_err(|e| {
                Error::Upgrade(format!(
                    "Refusing to cache archive for {version}: signature does not verify ({e})"
                ))
            })?;

        let archive_hash = sha256_file(archive_path)?;

        let dest_archive = self.cached_archive_path(version);
        let dest_sig = self.cached_signature_path(version);
        let meta_path = self.meta_path(version);

        Self::atomic_copy(
            archive_path,
            &dest_archive,
            &self
                .cache_dir
                .join(format!(".ant-node-{version}.archive.tmp")),
        )?;
        Self::atomic_copy(
            signature_path,
            &dest_sig,
            &self.cache_dir.join(format!(".ant-node-{version}.sig.tmp")),
        )?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Upgrade(format!("System clock error: {e}")))?
            .as_secs();

        let meta = CachedArchiveMeta {
            version: version.to_string(),
            archive_sha256: archive_hash,
            cached_at_epoch_secs: now,
        };

        let meta_json = serde_json::to_string(&meta).map_err(|e| {
            Error::Upgrade(format!("Failed to serialize cached archive metadata: {e}"))
        })?;

        // Metadata written last so a reader never sees a complete meta file
        // pointing at an incomplete archive/signature pair.
        let tmp_meta = self.cache_dir.join(format!(".ant-node-{version}.meta.tmp"));
        let mut f = File::create(&tmp_meta)?;
        f.write_all(meta_json.as_bytes())?;
        f.sync_all()?;
        drop(f);
        let _ = fs::remove_file(&meta_path);
        fs::rename(&tmp_meta, &meta_path)?;

        debug!(
            "Cached verified archive for version {version} at {}",
            dest_archive.display()
        );
        Ok(())
    }

    /// Acquire an exclusive download lock and return the guard.
    ///
    /// This prevents multiple nodes from downloading the same archive
    /// concurrently — the first acquires the lock and downloads, the rest
    /// wait and then find the archive already cached.
    ///
    /// The lock is released when the returned guard is dropped.
    ///
    /// **Note:** `lock_exclusive()` blocks the calling thread. Callers in
    /// async contexts should wrap this call in `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file cannot be created or acquired.
    pub fn acquire_download_lock(&self) -> Result<DownloadLockGuard> {
        let lock_path = self.cache_dir.join("download.lock");
        let lock = File::create(&lock_path)
            .map_err(|e| Error::Upgrade(format!("Failed to create download lock: {e}")))?;
        lock.lock_exclusive()
            .map_err(|e| Error::Upgrade(format!("Failed to acquire download lock: {e}")))?;
        Ok(DownloadLockGuard { _file: lock })
    }

    // -- private helpers -----------------------------------------------------

    /// Copy `src` to `dest` atomically via a temp file + rename.
    fn atomic_copy(src: &Path, dest: &Path, tmp: &Path) -> Result<()> {
        fs::copy(src, tmp)?;
        // Remove dest first on Windows where rename fails if it exists.
        let _ = fs::remove_file(dest);
        fs::rename(tmp, dest)?;
        Ok(())
    }

    fn meta_path(&self, version: &str) -> PathBuf {
        self.cache_dir.join(format!("ant-node-{version}.meta.json"))
    }
}

/// RAII guard that holds an exclusive download lock.
///
/// The underlying file lock is released when this guard is dropped.
pub struct DownloadLockGuard {
    _file: File,
}

/// Open `path` as a regular file with size at most `max_len`, validating
/// the metadata on the **opened handle** so a race between any prior stat
/// and the read cannot substitute a special file (FIFO/device/socket) or
/// an oversized payload. A symlink whose target is a regular file is
/// accepted (it's just an indirect path to a regular file — the attacker
/// who placed the link already needed write access to the cache dir, the
/// same access level as directly editing the regular file); a symlink
/// whose target is a special file is rejected by the `is_file()` check on
/// the opened handle.
///
/// Returns `(File, len)` on success; the returned `File` is positioned at
/// offset 0 and may be `io::copy`'d into a destination — callers should
/// wrap with `Read::take(max_len)` so an attacker who extends the file
/// after the metadata read cannot stream beyond the cap.
fn open_regular_capped(path: &Path, max_len: u64) -> io::Result<(File, u64)> {
    let file = OpenOptions::new().read(true).open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file (FIFO/device/socket/dir)",
        ));
    }
    let len = meta.len();
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("file exceeds size cap ({len} > {max_len})"),
        ));
    }
    Ok((file, len))
}

/// Compute the hex-encoded SHA-256 digest of a file.
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| Error::Upgrade(format!("Failed to read file for hashing: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey};
    use std::sync::OnceLock;
    use tempfile::TempDir;

    /// One generated keypair for the whole test module (keygen is expensive).
    fn test_keypair() -> &'static (MlDsaPublicKey, MlDsaSecretKey) {
        static KP: OnceLock<(MlDsaPublicKey, MlDsaSecretKey)> = OnceLock::new();
        KP.get_or_init(|| ml_dsa_65().generate_keypair().unwrap())
    }

    fn cache_with_test_key(dir: &Path) -> BinaryCache {
        BinaryCache::new_with_verify_key(dir.to_path_buf(), test_keypair().0.clone())
    }

    /// A caller-private staging directory (the per-upgrade temp dir in
    /// production). Returned so it outlives the call.
    fn priv_dir() -> TempDir {
        TempDir::new().unwrap()
    }

    /// Write an archive + a valid detached signature over it.
    fn make_signed_archive(dir: &Path, contents: &[u8]) -> (PathBuf, PathBuf) {
        let archive = dir.join("src-archive");
        fs::write(&archive, contents).unwrap();
        let sig = ml_dsa_65()
            .sign_with_context(&test_keypair().1, contents, signature::SIGNING_CONTEXT)
            .unwrap();
        let sig_path = dir.join("src-archive.sig");
        fs::write(&sig_path, sig.to_bytes()).unwrap();
        (archive, sig_path)
    }

    #[test]
    fn test_miss_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();
        assert!(cache.get_verified_archive("1.0.0", pd.path()).is_none());
    }

    #[test]
    fn test_store_and_get_verified_archive() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"signed archive bytes");
        cache.store_archive("1.2.3", &archive, &sig).unwrap();

        let got = cache
            .get_verified_archive("1.2.3", pd.path())
            .expect("cache hit");
        assert_eq!(fs::read(&got).unwrap(), b"signed archive bytes");
        // The returned path must be the PRIVATE copy, not the shared cache
        // file (that is what closes the verify/extract TOCTOU).
        assert!(
            got.starts_with(pd.path()),
            "returned archive must be the caller-private copy, got {got:?}"
        );
        assert_ne!(got, cache.cached_archive_path("1.2.3"));
    }

    #[test]
    fn test_store_rejects_unsigned_archive() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let archive = tmp.path().join("a");
        fs::write(&archive, b"unsigned").unwrap();
        let bad_sig = tmp.path().join("a.sig");
        fs::write(&bad_sig, vec![0u8; signature::SIGNATURE_SIZE]).unwrap();

        assert!(cache.store_archive("1.0.0", &archive, &bad_sig).is_err());
        assert!(cache.get_verified_archive("1.0.0", pd.path()).is_none());
    }

    /// An attacker who swaps the cached archive on disk (and even forges a
    /// matching SHA-256 in the metadata) cannot get it trusted, because
    /// the ML-DSA signature is re-verified on every hit.
    #[test]
    fn test_tampered_cached_archive_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"legit release archive");
        cache.store_archive("2.0.0", &archive, &sig).unwrap();
        assert!(cache.get_verified_archive("2.0.0", pd.path()).is_some());

        // Attacker overwrites the cached archive with a malicious payload...
        let cached_archive = cache.cached_archive_path("2.0.0");
        fs::write(&cached_archive, b"malicious payload").unwrap();

        // ...and forges the metadata SHA-256 so the corruption pre-check passes.
        let forged_hash = {
            let mut h = Sha256::new();
            h.update(b"malicious payload");
            hex::encode(h.finalize())
        };
        let meta = CachedArchiveMeta {
            version: "2.0.0".to_string(),
            archive_sha256: forged_hash,
            cached_at_epoch_secs: 0,
        };
        fs::write(
            cache.meta_path("2.0.0"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();

        // The SHA-256 pre-check now passes, but ML-DSA re-verification of the
        // swapped archive against the key fails → entry rejected.
        assert!(
            cache.get_verified_archive("2.0.0", pd.path()).is_none(),
            "tampered cache entry must NOT be trusted even with a forged \
             matching SHA-256 — the signature gate runs on every hit"
        );
    }

    /// TOCTOU defence: even if an attacker swaps the *shared* cache archive
    /// for malicious bytes immediately after a hit, the previously returned
    /// path (a caller-private copy) still contains the verified bytes, so
    /// what gets extracted/executed is exactly what was signature-verified.
    #[test]
    fn test_returned_archive_is_private_copy_immune_to_post_hit_swap() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"the real signed release");
        cache.store_archive("3.0.0", &archive, &sig).unwrap();

        let verified = cache
            .get_verified_archive("3.0.0", pd.path())
            .expect("cache hit");

        // Attacker swaps the SHARED cache archive right after verification.
        fs::write(
            cache.cached_archive_path("3.0.0"),
            b"post-verify malicious swap",
        )
        .unwrap();

        // The path the caller will extract from is the private copy and is
        // unaffected by the shared-file swap.
        assert_eq!(
            fs::read(&verified).unwrap(),
            b"the real signed release",
            "extraction must read the verified private bytes, not the \
             attacker's post-verification swap"
        );
    }

    #[test]
    fn test_missing_signature_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"data");
        cache.store_archive("1.0.0", &archive, &sig).unwrap();

        // Attacker deletes the signature to try to skip verification.
        fs::remove_file(cache.cached_signature_path("1.0.0")).unwrap();
        assert!(cache.get_verified_archive("1.0.0", pd.path()).is_none());
    }

    #[test]
    fn test_missing_meta_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();
        let (archive, sig) = make_signed_archive(tmp.path(), b"data");
        cache.store_archive("1.0.0", &archive, &sig).unwrap();
        fs::remove_file(cache.meta_path("1.0.0")).unwrap();
        assert!(cache.get_verified_archive("1.0.0", pd.path()).is_none());
    }

    /// Size policy: an attacker with cache-dir write cannot OOM/disk-exhaust
    /// the verifier by dropping a multi-GB archive — `get_verified_archive`
    /// stat-checks the cached archive against `MAX_ARCHIVE_SIZE_BYTES` BEFORE
    /// any copy or `fs::read` reaches `signature::verify_from_file`.
    #[test]
    fn test_oversize_cached_archive_is_rejected_before_copy() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        // Plant a real signed entry so the meta/sig pass earlier checks…
        let (archive, sig) = make_signed_archive(tmp.path(), b"legit");
        cache.store_archive("3.1.0", &archive, &sig).unwrap();
        // …then truncate-grow the cached archive past the limit.
        let cached_archive = cache.cached_archive_path("3.1.0");
        let oversize = crate::upgrade::apply::MAX_ARCHIVE_SIZE_BYTES as u64 + 1;
        {
            let f = File::create(&cached_archive).unwrap();
            f.set_len(oversize).unwrap();
        }

        // The size gate rejects pre-copy → no private archive ever staged.
        assert!(cache.get_verified_archive("3.1.0", pd.path()).is_none());
        let private_archive = pd.path().join("cached-3.1.0.archive");
        assert!(
            !private_archive.exists(),
            "oversize entry must NOT be staged into private dir"
        );
    }

    #[test]
    fn test_wrong_size_signature_is_rejected_before_copy() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"legit");
        cache.store_archive("3.2.0", &archive, &sig).unwrap();
        // Replace the cached signature with the wrong size.
        fs::write(cache.cached_signature_path("3.2.0"), b"too-short").unwrap();

        assert!(cache.get_verified_archive("3.2.0", pd.path()).is_none());
    }

    /// `store_archive` itself refuses to persist an oversize archive — even
    /// from a (hypothetically) misbehaving caller that bypassed the
    /// download-time size cap.
    #[test]
    fn test_store_archive_rejects_oversize() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());

        // Make a sparse "archive" past the limit and any signature.
        let big = tmp.path().join("big.archive");
        {
            let f = File::create(&big).unwrap();
            f.set_len(crate::upgrade::apply::MAX_ARCHIVE_SIZE_BYTES as u64 + 1)
                .unwrap();
        }
        let any_sig = tmp.path().join("any.sig");
        fs::write(&any_sig, vec![0u8; signature::SIGNATURE_SIZE]).unwrap();

        assert!(cache.store_archive("9.9.9", &big, &any_sig).is_err());
    }

    /// Round-3 regression: a cache-dir writer cannot bypass the size gate
    /// by planting a symlink whose `stat(2)` size is small but whose
    /// target reads indefinitely (e.g. `/dev/zero`). `symlink_metadata`
    /// + `is_file()` rejects the entry before any `fs::copy` reads it.
    #[cfg(unix)]
    #[test]
    fn test_symlink_cached_archive_is_rejected_before_copy() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        // Plant a legit signed entry so meta/version/sig-size are good…
        let (archive, sig) = make_signed_archive(tmp.path(), b"legit");
        cache.store_archive("4.0.0", &archive, &sig).unwrap();
        // …then replace the cached archive with a symlink to /dev/zero.
        let cached_archive = cache.cached_archive_path("4.0.0");
        fs::remove_file(&cached_archive).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &cached_archive).unwrap();

        assert!(
            cache.get_verified_archive("4.0.0", pd.path()).is_none(),
            "a symlinked cached archive must be rejected pre-copy, \
             not chased into /dev/zero"
        );
        // Nothing should have been staged.
        assert!(!pd.path().join("cached-4.0.0.archive").exists());
    }

    /// `.meta.json` is read through the same size/file-type gate as the
    /// archive and signature: planting a multi-MB metadata file (or a
    /// metadata symlink to a special file) is rejected pre-parse without
    /// risking a hang or large allocation.
    #[test]
    fn test_oversized_meta_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        // Establish a valid entry so archive/sig are well-formed.
        let (archive, sig) = make_signed_archive(tmp.path(), b"legit");
        cache.store_archive("5.0.0", &archive, &sig).unwrap();

        // Overwrite meta with a file well above MAX_META_BYTES of garbage.
        let meta_path = cache.meta_path("5.0.0");
        let huge = vec![b'a'; usize::try_from(MAX_META_BYTES).unwrap_or(usize::MAX) + 1024];
        fs::write(&meta_path, &huge).unwrap();

        assert!(
            cache.get_verified_archive("5.0.0", pd.path()).is_none(),
            "oversized metadata file must be rejected before parsing"
        );
    }

    /// `.meta.json` planted as a symlink to a special file (e.g.
    /// `/dev/zero`) is rejected by the open-handle file-type check,
    /// without hanging or OOM'ing on the read.
    #[cfg(unix)]
    #[test]
    fn test_meta_symlink_to_special_file_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let cache = cache_with_test_key(tmp.path());
        let pd = priv_dir();

        let (archive, sig) = make_signed_archive(tmp.path(), b"legit");
        cache.store_archive("5.1.0", &archive, &sig).unwrap();

        let meta_path = cache.meta_path("5.1.0");
        fs::remove_file(&meta_path).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &meta_path).unwrap();

        assert!(
            cache.get_verified_archive("5.1.0", pd.path()).is_none(),
            "metadata symlink to a special file must be rejected"
        );
    }
}
