//! ant-devnet under stop signals (ant-node#261).
//!
//! SIGTERM, from `kill`, a service manager or `ant dev stop`, used to kill
//! ant-devnet outright: the devnet was never shut down, Anvil was orphaned
//! still holding its port, and the data directory was left behind. These
//! tests run the real binary and check that a SIGTERM, while running or
//! part-way through startup, now shuts it down cleanly, removing only the
//! run's own directory, and that the directory a run killed by `SIGKILL`
//! has to leave behind is removed by the next run.
//!
//! The binary runs with `HOME` and `XDG_DATA_HOME` pointed at a temporary
//! directory, so its default data root, and anything it removes, is inside
//! the test's own directory. `anvil` must be on `PATH` (CI installs Foundry).

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ant_node::devnet::MARKER_FILE;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Long enough for a 5-node devnet with Anvil on a loaded CI runner.
const STARTUP_TIMEOUT: Duration = Duration::from_mins(4);
/// How long a stopped devnet may take to shut down and exit.
const EXIT_TIMEOUT: Duration = Duration::from_mins(1);

/// A running ant-devnet, stopped if a test fails before stopping it.
struct Devnet(Child);

impl Drop for Devnet {
    /// SIGTERM first: ant-devnet then stops Anvil itself. SIGKILL skips the
    /// destructors that do that, so when it comes to SIGKILL, Anvil, its one
    /// child process, is killed first rather than orphaned.
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(None)) {
            return;
        }
        let pid = self.0.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid]).status();
        let deadline = Instant::now() + EXIT_TIMEOUT;
        while Instant::now() < deadline {
            if !matches!(self.0.try_wait(), Ok(None)) {
                return;
            }
            sleep(Duration::from_millis(100));
        }
        let _ = Command::new("pkill").args(["-KILL", "-P", &pid]).status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Devnet {
    fn spawn(home: &Path, args: &[&str]) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ant-devnet"))
            .args(args)
            .env("HOME", home)
            .env("XDG_DATA_HOME", home.join("data"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ant-devnet");
        Self(child)
    }

    /// Send `signal` (a name `kill` accepts, e.g. "TERM") to the devnet,
    /// through the system `kill` so the test needs no unsafe code.
    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .arg(format!("-{signal}"))
            .arg(self.0.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} {} failed", self.0.id());
    }

    fn wait_for_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + EXIT_TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait().expect("try_wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "ant-devnet still running {}s after the stop signal",
                EXIT_TIMEOUT.as_secs()
            );
            sleep(Duration::from_millis(100));
        }
    }

    /// Fail if the devnet exited on its own, e.g. a startup error.
    fn assert_running(&mut self) {
        if let Some(status) = self.0.try_wait().expect("try_wait") {
            panic!("ant-devnet exited early with {status}");
        }
    }
}

/// Poll until `ready` returns `Some`, or fail after `STARTUP_TIMEOUT`.
fn wait_until<T>(devnet: &mut Devnet, what: &str, mut ready: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(value) = ready() {
            return value;
        }
        devnet.assert_running();
        assert!(
            Instant::now() < deadline,
            "timed out after {}s waiting for {what}",
            STARTUP_TIMEOUT.as_secs()
        );
        sleep(Duration::from_millis(200));
    }
}

/// The run directories in `parent`: those with a run marker.
fn run_dirs(parent: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(parent)
        .map(|entries| {
            entries
                .filter_map(|entry| Some(entry.ok()?.path()))
                .filter(|dir| dir.join(MARKER_FILE).is_file())
                .collect()
        })
        .unwrap_or_default()
}

fn read_manifest(path: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// `http://host:port/` → every address the host resolves to. `localhost`
/// can resolve to `::1` first while Anvil listens on `127.0.0.1`.
fn rpc_addrs(rpc_url: &str) -> Vec<SocketAddr> {
    let host_port = rpc_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let addrs: Vec<SocketAddr> = host_port
        .to_socket_addrs()
        .expect("rpc_url resolves")
        .collect();
    assert!(!addrs.is_empty(), "{rpc_url} resolves to no address");
    addrs
}

fn accepting(addrs: &[SocketAddr]) -> bool {
    addrs
        .iter()
        .any(|addr| TcpStream::connect_timeout(addr, Duration::from_millis(500)).is_ok())
}

#[test]
fn sigterm_while_running_removes_the_data_dir_and_stops_anvil() {
    let home = tempfile::tempdir().unwrap();
    let manifest_path = home.path().join("manifest.json");
    let mut devnet = Devnet::spawn(
        home.path(),
        &[
            "--preset",
            "minimal",
            "--enable-evm",
            "--manifest",
            manifest_path.to_str().unwrap(),
        ],
    );

    let manifest = wait_until(&mut devnet, "the manifest", || {
        read_manifest(&manifest_path)
    });
    let data_dir = PathBuf::from(manifest["data_dir"].as_str().expect("data_dir"));
    let anvil = rpc_addrs(manifest["evm"]["rpc_url"].as_str().expect("evm.rpc_url"));

    // The default data directory is a fresh one for this run, inside the
    // (redirected) ant data root's devnets directory.
    assert!(data_dir.starts_with(home.path()), "{}", data_dir.display());
    assert_eq!(
        data_dir.parent().and_then(Path::file_name),
        Some(std::ffi::OsStr::new("devnets")),
        "{}",
        data_dir.display()
    );
    assert!(
        data_dir.join(MARKER_FILE).is_file(),
        "{}",
        data_dir.display()
    );
    assert!(accepting(&anvil), "Anvil is not listening on {anvil:?}");

    devnet.signal("TERM");
    let status = devnet.wait_for_exit();

    assert!(status.success(), "ant-devnet exited with {status}");
    assert!(!data_dir.exists(), "{} was left behind", data_dir.display());
    assert!(data_dir.parent().is_some_and(Path::is_dir));
    // Anvil is stopped, so nothing listens on its port any more.
    let deadline = Instant::now() + Duration::from_secs(10);
    while accepting(&anvil) {
        assert!(
            Instant::now() < deadline,
            "Anvil still listening on {anvil:?}"
        );
        sleep(Duration::from_millis(200));
    }
}

#[test]
fn sigterm_during_startup_removes_the_run_dir_only() {
    let home = tempfile::tempdir().unwrap();
    // `--data-dir` names the directory the run creates its own in.
    let data_dir = home.path().join("devnet");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("sentinel"), b"not the devnet's").unwrap();
    let manifest_path = home.path().join("manifest.json");
    // Ten nodes a second apart: startup takes at least ten seconds, so the
    // signal lands while nodes are still being spawned.
    let mut devnet = Devnet::spawn(
        home.path(),
        &[
            "--preset",
            "small",
            "--spawn-delay-ms",
            "1000",
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--manifest",
            manifest_path.to_str().unwrap(),
        ],
    );

    let run = wait_until(&mut devnet, "the first node directory", || {
        run_dirs(&data_dir).into_iter().find(|run| {
            std::fs::read_dir(run.join("nodes"))
                .ok()
                .and_then(|mut entries| entries.next())
                .is_some()
        })
    });
    assert!(
        !manifest_path.exists(),
        "startup finished before the signal; the test needs a slower startup"
    );

    devnet.signal("TERM");
    let status = devnet.wait_for_exit();

    assert!(status.success(), "ant-devnet exited with {status}");
    assert!(!run.exists(), "{} was left behind", run.display());
    assert!(data_dir.join("sentinel").is_file());
    assert!(
        !manifest_path.exists(),
        "a devnet stopped during startup must not write a manifest"
    );
}

#[test]
fn the_next_run_removes_what_a_sigkilled_run_left() {
    let home = tempfile::tempdir().unwrap();
    let data_dir = home.path().join("devnets");
    let other = data_dir.join("not-a-run");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("sentinel"), b"not the devnet's").unwrap();
    let args = [
        "--preset",
        "minimal",
        "--data-dir",
        data_dir.to_str().unwrap(),
    ];

    let mut killed = Devnet::spawn(home.path(), &args);
    let left = wait_until(&mut killed, "the run directory", || {
        run_dirs(&data_dir).pop()
    });
    killed.signal("KILL");
    killed.wait_for_exit();
    // SIGKILL can't be caught, so the run could not remove its directory.
    assert!(left.join(MARKER_FILE).is_file(), "{}", left.display());

    let mut next = Devnet::spawn(home.path(), &args);
    // It removes it before it creates its own.
    let runs = wait_until(&mut next, "the next run to replace it", || {
        let runs = run_dirs(&data_dir);
        (!left.exists() && !runs.is_empty()).then_some(runs)
    });
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert!(other.join("sentinel").is_file());

    next.signal("TERM");
    let status = next.wait_for_exit();
    assert!(status.success(), "ant-devnet exited with {status}");
    assert!(run_dirs(&data_dir).is_empty());
    assert!(other.join("sentinel").is_file());
}
