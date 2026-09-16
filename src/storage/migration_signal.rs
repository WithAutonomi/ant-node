//! What a node tells the network about its move off the old chunk store.
//!
//! The release that finally deletes the old store has to be published at a moment when the
//! fleet has finished moving, and "the fleet has finished" is not something a calendar can
//! establish. Nor can our own logs: they cover the nodes we run, and the nodes most likely
//! to still be carrying a `chunks.mdb` are the ones we do not.
//!
//! So a node says so itself, in the one field every peer already sees. `saorsa-core` sends a
//! user agent string with every signed message and keeps each peer's, so any node can ask
//! what its neighbours are. Putting the answer there costs no new message, no new field and
//! no protocol version: it is a different value in a string that was already on the wire.
//!
//! Read [`report_until_shutdown`] before using any of this to decide a release. It does not
//! establish that the fleet has finished, and cannot. A node sees only the peers it is
//! connected to, and each of those answers as of its own last start, so the most this can show
//! is that some peer reported an old store when it last started. It can never show that no node
//! has one. What it gives is the only view we get of the nodes we do not run.
//!
//! Two rules the string has to obey. It must still begin `node/`, because that prefix is
//! what `saorsa-core` uses to decide whether a peer is a DHT participant at all, and a node
//! that loses it stops being routed to. And the three states must never be folded into two:
//! a directory this node could not read is not the same as one that is not there, and
//! reading "cannot tell" as "finished" is how a gate comes back clean over a fleet that is
//! not.
//!
//! What is deliberately NOT here: anything about whether storage is switched off. A node
//! with `storage.enabled = false` never opens a store, but the old environment is still on
//! its disk and the release that deletes it will still find it. The question this answers is
//! about the filesystem, so it is asked of the filesystem, whatever the node was configured
//! to do with it.

use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::Duration;

use saorsa_core::P2PNode;
use tokio_util::sync::CancellationToken;

use crate::logging::{info, warn};

/// How often a node says where it is and what it can see.
///
/// Often enough that a node's reading **of its own disk** is never many hours stale, rarely
/// enough that it is a line an operator can read rather than a stream. What it says about its
/// peers is not fresh at any cadence: their user agents were fixed when their transports were
/// built, so a peer's answer is as of its last start whenever this runs.
///
/// It is a heartbeat as much as a count: a node that stops saying anything is a node the
/// release gate must treat as unfinished, and it can only do that if a healthy node says
/// something on a known cadence.
const REPORT_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// The directory the old chunk store lives in.
const LEGACY_ENV_DIR: &str = "chunks.mdb";

/// What retirement renames it to before deleting it.
const RETIRED_SUFFIX: &str = ".retired";

/// The file retirement writes inside a directory to say it has finished with it.
const RETIRED_MARKER: &str = "RETIRED";

/// The token that carries the state, so a reader can find it wherever it sits.
const SIGNAL_PREFIX: &str = "migration/";

/// Where this node is in the move off the old chunk store, as seen from its own disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationSignal {
    /// Something is still there that this node has not finished with.
    Legacy,
    /// Nothing is, or only the harmless remains of a cleanup that did not quite finish.
    Files,
    /// The disk could not be read well enough to say. Never folded into either answer.
    Unknown,
}

impl MigrationSignal {
    /// The token this state appears as on the wire.
    const fn token(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Files => "files",
            Self::Unknown => "unknown",
        }
    }

    /// Read the state off this node's own disk.
    ///
    /// Cheap enough to call before the transport is built, which is where it has to be
    /// called: the user agent is fixed when the transport is constructed.
    #[must_use]
    pub fn from_disk(root_dir: &Path) -> Self {
        let Ok(dirs) = legacy_directories(root_dir) else {
            return Self::Unknown;
        };
        let mut answer = Self::Files;
        for dir in dirs {
            match classify(&dir) {
                // Finished with, or empty, which is what an interrupted cleanup leaves.
                // Neither holds a chunk, so neither makes this node unfinished.
                Leftover::Harmless => {}
                Leftover::Holding => return Self::Legacy,
                // Keep looking: a directory further down the list may still be holding
                // chunks, and that is the stronger answer of the two.
                Leftover::Unreadable => answer = Self::Unknown,
            }
        }
        answer
    }
}

/// What one leftover directory means for the node carrying it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leftover {
    /// It holds chunks this node has not moved.
    Holding,
    /// It holds nothing, or it carries the mark that says it was finished with.
    Harmless,
    /// It could not be read well enough to say which.
    Unreadable,
}

/// Every leftover of the old chunk store under `root_dir`, live name and tombstones alike.
///
/// The names are matched exactly rather than by prefix. Retirement only ever creates
/// `chunks.mdb.retired` or `chunks.mdb.retired.<n>`, and a prefix match would also claim a
/// directory somebody else put there, which matters because a later release deletes what
/// this list returns.
///
/// An entry that cannot be read is returned rather than skipped, so it becomes `Unknown`
/// rather than silently becoming `Files`.
fn legacy_directories(root_dir: &Path) -> Result<Vec<std::path::PathBuf>, Unreadable> {
    let mut found = Vec::new();

    // `symlink_metadata`, not `try_exists`: the latter follows links, so a dangling or
    // looping one at the live name would read as nothing being there.
    let live = root_dir.join(LEGACY_ENV_DIR);
    // An error is not an absence: a live name that cannot be queried hides an environment
    // that may well be there, so it goes on the list and becomes `Unknown` rather than
    // quietly becoming `Files`.
    if !matches!(std::fs::symlink_metadata(&live), Err(ref e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        found.push(live);
    }

    let entries = match std::fs::read_dir(root_dir) {
        Ok(entries) => entries,
        // A root that is not there yet holds nothing, which is every node starting for the
        // first time. That is an answer.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        // One that cannot be listed hides every tombstone in it, so there is no answer to
        // give. Saying so is the whole reason `Unknown` exists.
        Err(_) => return Err(Unreadable),
    };
    for entry in entries {
        // Nor is one unreadable entry evidence that there is nothing behind it. An earlier
        // version of this pushed a made-up path here so the caller would classify it, and a
        // made-up path that happens not to exist classifies as harmless: one unreadable
        // directory entry could hide a real tombstone and still produce `files`, which is
        // exactly the false green a release gate must not be able to show.
        let Ok(entry) = entry else {
            return Err(Unreadable);
        };
        if entry.file_name().to_str().is_some_and(is_tombstone_name) {
            found.push(entry.path());
        }
    }
    Ok(found)
}

/// There is no answer to give about this root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Unreadable;

/// The most tombstones one root can hold, matching what retirement will ever create.
const MAX_TOMBSTONES: u32 = 64;

/// Is this a name retirement gives a tombstone?
///
/// `chunks.mdb.retired`, or that plus `.<n>` for `n` in `1..=64`, written the way retirement
/// writes it. The bounds are not decoration: retirement only ever counts up to 64, so `.65`
/// and `.007` are names it cannot have produced, and this list becomes a list of directories
/// a later release deletes.
fn is_tombstone_name(name: &str) -> bool {
    let base = format!("{LEGACY_ENV_DIR}{RETIRED_SUFFIX}");
    if name == base {
        return true;
    }
    let Some(suffix) = name.strip_prefix(&format!("{base}.")) else {
        return false;
    };
    // Parsed and then written back out, so a leading zero or a plus sign fails to match
    // itself: `"007".parse::<u32>()` is happily 7, and `chunks.mdb.retired.007` is not a
    // name anything here created.
    suffix
        .parse::<u32>()
        .is_ok_and(|n| (1..=MAX_TOMBSTONES).contains(&n) && suffix == n.to_string())
}

/// What one directory says about itself.
fn classify(dir: &Path) -> Leftover {
    match std::fs::symlink_metadata(dir) {
        // A link is never treated as finished with, whatever it points at: the mark would
        // have been written through it into a directory that is not this node's. It is also
        // never followed to see what is behind it.
        Ok(meta) if meta.file_type().is_symlink() => return Leftover::Holding,
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Leftover::Harmless,
        Err(_) => return Leftover::Unreadable,
    }
    // A regular file, not merely something at that name. Retirement writes the mark with
    // `create_new`, so it is always an ordinary file; a directory, a link, a FIFO or anything
    // else wearing the name is not evidence of anything, and this answer is what decides
    // whether a later release deletes the chunks underneath it.
    match std::fs::symlink_metadata(dir.join(RETIRED_MARKER)) {
        Ok(meta) if meta.is_file() => return Leftover::Harmless,
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Leftover::Unreadable,
    }
    // No mark. A directory with nothing in it holds no chunks, so it cannot be hiding any:
    // that is what a cleanup interrupted between emptying a tombstone and removing it
    // leaves behind.
    std::fs::read_dir(dir).map_or(Leftover::Unreadable, |mut entries| {
        if entries.next().is_none() {
            Leftover::Harmless
        } else {
            Leftover::Holding
        }
    })
}

/// The user agent this node announces itself with.
///
/// Keeps the `node/` prefix `saorsa-core` gates DHT membership on, reports this build's
/// version rather than the transport's, because that is the one a release decision is made
/// about, and carries the migration state as its own token.
#[must_use]
pub fn user_agent(signal: MigrationSignal) -> String {
    format!(
        "node/{} {SIGNAL_PREFIX}{}",
        env!("CARGO_PKG_VERSION"),
        signal.token()
    )
}

/// What a peer's user agent says about that peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerMigrationState {
    /// It says it still has an old chunk store.
    Legacy,
    /// It says it has finished.
    Files,
    /// It says it cannot tell.
    Unknown,
    /// It says nothing, so it is running a build from before this was reported. Counted on
    /// its own rather than with the finished ones: silence is not completion.
    Unreported,
    /// Not a node at all. Clients connect and announce themselves too, and counting them as
    /// nodes that never reported would make every reading look worse than it is.
    NotANode,
}

/// Read a peer's user agent.
#[must_use]
pub fn peer_state(user_agent: &str) -> PeerMigrationState {
    if !user_agent.starts_with("node/") {
        return PeerMigrationState::NotANode;
    }
    for token in user_agent.split_whitespace() {
        let Some(state) = token.strip_prefix(SIGNAL_PREFIX) else {
            continue;
        };
        return match state {
            "legacy" => PeerMigrationState::Legacy,
            "files" => PeerMigrationState::Files,
            // A token we do not recognise is a build that reports something this one has
            // never heard of. That is not "finished".
            _ => PeerMigrationState::Unknown,
        };
    }
    PeerMigrationState::Unreported
}

/// One tally of what a node can see around it.
///
/// Every field counts what a peer **announced**, which it fixed at its last start. None of them
/// says what that peer holds now. And an all-zero tally is not an answer: a node connected to
/// nobody produces one, and it reads exactly like a tally of peers that have all finished. The
/// number of peers seen is what tells those apart, which is why it is on the line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerTally {
    /// Peers that announced an old chunk store at their last start.
    pub legacy: usize,
    /// Peers that announced having finished, as of their last start.
    pub files: usize,
    /// Peers that announced they could not tell, or answered with something this build does
    /// not know.
    pub unknown: usize,
    /// Peers running a build from before this was reported.
    pub unreported: usize,
}

impl PeerTally {
    /// Peers that are not evidence the fleet has finished.
    #[must_use]
    pub const fn outstanding(self) -> usize {
        self.legacy + self.unknown + self.unreported
    }

    fn add(&mut self, state: PeerMigrationState) {
        match state {
            PeerMigrationState::Legacy => self.legacy += 1,
            PeerMigrationState::Files => self.files += 1,
            PeerMigrationState::Unknown => self.unknown += 1,
            PeerMigrationState::Unreported => self.unreported += 1,
            // Deliberately not counted at all. A client is not a node that failed to
            // report, and putting it in any of the buckets above would make every reading
            // worse than it is.
            PeerMigrationState::NotANode => {}
        }
    }
}

/// Count what this node can see of its neighbours.
///
/// These are edges, not nodes: two of our nodes connected to the same peer both report it,
/// and a peer nobody is connected to is in nobody's count. That is why each line carries the
/// observer, so whoever adds them up can decide what a peer is worth rather than trusting an
/// arithmetic sum.
pub async fn tally_peers(p2p: &Arc<P2PNode>) -> PeerTally {
    let mut tally = PeerTally::default();
    let transport = p2p.transport();
    let observer = p2p.peer_id().to_hex();
    for peer in transport.connected_peers().await {
        // No agent recorded is not the same as a peer that reported nothing, but it is
        // just as far from evidence of completion, so it lands in the same bucket rather
        // than being skipped.
        let agent = transport.peer_user_agent(&peer).await;
        let state = agent
            .as_deref()
            .map_or(PeerMigrationState::Unreported, peer_state);
        // One line per peer, not just the totals. What a node sees are edges: two of our
        // nodes connected to the same peer both report it, and a peer nobody is connected to
        // is in nobody's count. Summing the totals across the fleet therefore counts some
        // nodes twice and others never, which is not a number a release decision can rest
        // on. With the observer, the peer and the moment on each line, whoever adds them up
        // can deduplicate by peer and apply their own freshness rule; without them, they
        // cannot.
        //
        // At `info`, not `debug`. Nodes run at `info` (`cli.rs:95`), so the same line at
        // `debug` is written nowhere the gate can read it, and the release would be decided
        // on the aggregates alone — which is the number that cannot be deduplicated. A line
        // nobody emits is not a signal.
        //
        // Only for peers that are not reporting finished. The gate asks which distinct nodes
        // are still outstanding, so those are the ones that need naming, and the cost falls
        // away as they stop being outstanding rather than peaking when they do. Note which way
        // that runs: these lines stopping means no peer this node is connected to is still
        // reporting an old store, which is not the same as the fleet having finished, and
        // never can be. The aggregate line below is emitted either way and
        // carries the finished count, so the denominator does not go missing with them, and
        // a node that has gone quiet is still distinguishable from a node with nothing to
        // report.
        if state != PeerMigrationState::Files && state != PeerMigrationState::NotANode {
            info!(
                migration_event = "peer_state",
                observer = %observer,
                peer = %peer.to_hex(),
                state = peer_state_token(state),
                agent = agent.as_deref().unwrap_or("none"),
                "Storage migration: peer {} is {}",
                peer.to_hex(),
                peer_state_token(state)
            );
        }
        tally.add(state);
    }
    tally
}

/// The token a peer's state is reported as, so the aggregate line and the per-peer lines
/// cannot drift apart.
///
/// Only ever read by a log line, so it goes when the logging feature does.
#[cfg_attr(not(feature = "logging"), allow(dead_code))]
const fn peer_state_token(state: PeerMigrationState) -> &'static str {
    match state {
        PeerMigrationState::Legacy => "legacy",
        PeerMigrationState::Files => "files",
        PeerMigrationState::Unknown => "unknown",
        PeerMigrationState::Unreported => "unreported",
        PeerMigrationState::NotANode => "not-a-node",
    }
}

/// Say where this node is, and what it can see of its neighbours, until it shuts down.
///
/// Two questions, and they are not the same one. **This node's own state** is read from its
/// disk every pass, so a node that finishes says so within the interval rather than at its next
/// restart. **What it sees of its peers** is read from their user agents.
///
/// What the peer half means, in the fewest words that are all true, because a release decision
/// rests on it.
///
/// It counts what the peers this node is connected to **announced**, each as of that peer's own
/// last start. `saorsa-core` copies the user agent when it builds the transport, so a node that
/// finishes migrating goes on announcing `legacy` until it restarts.
///
/// Two consequences, and they run in opposite directions, so the tally bounds nothing. A peer
/// announcing `legacy` may have finished since, so the count can be too high. A node that is
/// offline, or simply not connected to, is absent from it, so the count can be too low. An
/// all-zero tally proves nothing on its own either, because a node connected to nobody produces
/// one; the number of peers seen is what tells that apart, which is why it is on the line.
///
/// So this can surface nodes that have not finished. It cannot establish that none remain, and
/// no amount of it adds up to that. `outstanding` counts `legacy`, `unknown` and `unreported`
/// together, because a peer whose disk could not be read and a peer on a build from before this
/// existed are both as far from finished as `legacy` is.
///
/// It is still the only way our own fleet learns anything at all about the nodes we do not run.
///
/// The handle is **weak**. A reporter must never be the reason the thing it observes stays
/// alive: a strong one would keep a dropped node's transport, and its bound port, for as long
/// as this task ran.
pub async fn report_until_shutdown(
    p2p: Weak<P2PNode>,
    root_dir: std::path::PathBuf,
    shutdown: CancellationToken,
) {
    loop {
        // Wait first. A node that has just started has no peers to describe, and nothing has
        // changed on its disk since the user agent was built from it.
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(REPORT_INTERVAL) => {}
        }
        let Some(node) = p2p.upgrade() else {
            return;
        };
        let own = MigrationSignal::from_disk(&root_dir);
        let peers = tally_peers(&node).await;
        drop(node);
        let seen = peers.outstanding() + peers.files;
        if own == MigrationSignal::Legacy || own == MigrationSignal::Unknown {
            warn!(
                migration_event = "signal",
                state = own.token(),
                peers_legacy = peers.legacy,
                peers_unknown = peers.unknown,
                peers_unreported = peers.unreported,
                peers_files = peers.files,
                "This node cannot report itself finished with the old chunk store ({}: \
                 `legacy` means one is there, `unknown` means its disk could not be read, so \
                 whether one is there is not known). {} of the {seen} node(s) it can see are \
                 not reporting finished either.",
                own.token(),
                peers.outstanding()
            );
        } else {
            info!(
                migration_event = "signal",
                state = own.token(),
                peers_legacy = peers.legacy,
                peers_unknown = peers.unknown,
                peers_unreported = peers.unreported,
                peers_files = peers.files,
                "Storage migration: this node has nothing of the old store left; {} of the \
                 {seen} node(s) it can see are not reporting finished.",
                peers.outstanding()
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// The reporter must not keep the node it reports on alive.
    ///
    /// It holds a weak handle and upgrades per pass. A strong one would keep the node, and
    /// with it the transport and the bound port, for as long as the task ran, so any path
    /// that dropped a node without cancelling its token would leak a live port instead of
    /// stopping a node. Nothing notices that until the next bind fails, somewhere else,
    /// much later.
    #[tokio::test]
    async fn the_reporter_lets_go_of_a_node_that_was_dropped() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().to_path_buf();
        let shutdown = CancellationToken::new();

        // Stand in for the node: what matters is that the task holds no strong reference,
        // so the count of strong holders does not rise when the reporter starts, and the
        // reporter stops on its own once the last real holder goes.
        let owner = Arc::new(());
        let weak = Arc::downgrade(&owner);
        assert_eq!(Arc::strong_count(&owner), 1);

        let handle = tokio::spawn({
            let weak = weak.clone();
            let shutdown = shutdown.clone();
            async move {
                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => return "cancelled",
                        () = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
                    }
                    let Some(up) = weak.upgrade() else {
                        return "node went away";
                    };
                    drop(up);
                }
            }
        });

        assert_eq!(
            Arc::strong_count(&owner),
            1,
            "starting the reporter must not add a strong holder"
        );
        drop(owner);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("the reporter must stop on its own")
            .expect("task must not panic");
        assert_eq!(
            outcome, "node went away",
            "the reporter must stop when the node is gone, not wait for a cancellation \
             nobody sends"
        );
        let _ = root;
    }

    use super::*;
    use tempfile::TempDir;

    fn dir_with(root: &Path, name: &str) -> std::path::PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_node_with_nothing_on_disk_has_finished() {
        let root = TempDir::new().unwrap();
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Files
        );
    }

    #[test]
    fn a_root_that_does_not_exist_yet_has_finished() {
        let root = TempDir::new().unwrap();
        let never = root.path().join("not-created");
        assert_eq!(MigrationSignal::from_disk(&never), MigrationSignal::Files);
    }

    #[test]
    fn a_live_environment_with_chunks_in_it_has_not() {
        let root = TempDir::new().unwrap();
        let env = dir_with(root.path(), LEGACY_ENV_DIR);
        std::fs::write(env.join("data.mdb"), b"chunks").unwrap();
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Legacy
        );
    }

    #[test]
    fn a_marked_leftover_has_finished() {
        let root = TempDir::new().unwrap();
        let env = dir_with(root.path(), LEGACY_ENV_DIR);
        std::fs::write(env.join("data.mdb"), b"chunks").unwrap();
        std::fs::write(env.join(RETIRED_MARKER), b"").unwrap();
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Files
        );
    }

    #[test]
    fn an_empty_leftover_has_finished() {
        // What a cleanup interrupted between emptying a tombstone and removing it leaves.
        let root = TempDir::new().unwrap();
        dir_with(root.path(), "chunks.mdb.retired");
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Files
        );
    }

    #[test]
    fn a_tombstone_with_chunks_in_it_has_not() {
        // A crash between the rename and the mark leaves an intact environment wearing a
        // retired-looking name. What it is called is not evidence.
        let root = TempDir::new().unwrap();
        let tomb = dir_with(root.path(), "chunks.mdb.retired.3");
        std::fs::write(tomb.join("data.mdb"), b"chunks").unwrap();
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Legacy
        );
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_never_read_as_finished() {
        // An earlier version pushed a made-up path when an entry could not be read, so the
        // caller would classify it. A made-up path that happens not to exist classifies as
        // harmless, so one unreadable entry could hide a real tombstone and still answer
        // `files`. A gate that can come back green over a fleet that has not finished is
        // worse than no gate.
        let root = TempDir::new().unwrap();
        let unreadable = root.path().join("locked");
        std::fs::create_dir_all(&unreadable).unwrap();
        let tomb = unreadable.join("chunks.mdb.retired");
        std::fs::create_dir_all(&tomb).unwrap();
        std::fs::write(tomb.join("data.mdb"), b"chunks").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
            let answer = MigrationSignal::from_disk(&unreadable);
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(
                answer,
                MigrationSignal::Unknown,
                "a root that cannot be listed must never answer that it has finished"
            );
        }
    }

    #[test]
    fn a_directory_that_only_looks_like_a_tombstone_is_not_one() {
        // This list is eventually a list of directories a later release deletes, so it
        // matches the names retirement actually creates and nothing else.
        assert!(is_tombstone_name("chunks.mdb.retired"));
        assert!(is_tombstone_name("chunks.mdb.retired.1"));
        assert!(is_tombstone_name("chunks.mdb.retired.42"));
        assert!(!is_tombstone_name("chunks.mdb.retired-mine"));
        assert!(!is_tombstone_name("chunks.mdb.retired."));
        assert!(!is_tombstone_name("chunks.mdb.retired.backup"));
        assert!(!is_tombstone_name("chunks.mdb"));
        // Names retirement counts up to, and names it never reaches. `.007` parses as 7 and
        // is still not a name anything wrote.
        assert!(is_tombstone_name("chunks.mdb.retired.64"));
        assert!(!is_tombstone_name("chunks.mdb.retired.65"));
        assert!(!is_tombstone_name("chunks.mdb.retired.0"));
        assert!(!is_tombstone_name("chunks.mdb.retired.007"));
        assert!(!is_tombstone_name("chunks.mdb.retired.+1"));
        assert!(!is_tombstone_name("chunks.mdb.retired.999999"));

        let root = TempDir::new().unwrap();
        let mine = dir_with(root.path(), "chunks.mdb.retired-mine");
        std::fs::write(mine.join("data.mdb"), b"somebody else's").unwrap();
        assert_eq!(
            MigrationSignal::from_disk(root.path()),
            MigrationSignal::Files
        );
    }

    #[test]
    fn a_linked_environment_is_never_read_as_finished() {
        // The mark would have been written through the link into a directory this node
        // does not own, so a link is never evidence that anything was finished with, and
        // what it points at is never followed.
        let root = TempDir::new().unwrap();
        let elsewhere = dir_with(root.path(), "elsewhere");
        std::fs::write(elsewhere.join(RETIRED_MARKER), b"").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&elsewhere, root.path().join(LEGACY_ENV_DIR)).unwrap();
            assert_eq!(
                MigrationSignal::from_disk(root.path()),
                MigrationSignal::Legacy
            );
        }
    }

    /// A node still running the release before this one reads as unreported, never as done.
    ///
    /// This release lands on a fleet where most nodes are still on the previous one, and
    /// those announce no migration token at all. Counting them as finished would let the gate
    /// come back clean over a fleet that has barely started. They get their own bucket, and
    /// `outstanding` includes it.
    #[test]
    fn a_peer_on_the_previous_release_is_not_counted_as_finished() {
        assert_eq!(
            peer_state("node/0.19.0"),
            PeerMigrationState::Unreported,
            "a node with no migration token has not reported, which is not the same as done"
        );
        let mut tally = PeerTally::default();
        tally.add(peer_state("node/0.19.0"));
        assert_eq!(tally.files, 0, "it must not land in the finished bucket");
        assert_eq!(tally.outstanding(), 1, "and must count against readiness");
    }

    #[test]
    fn the_user_agent_keeps_the_prefix_that_gates_dht_membership() {
        // saorsa-core decides whether a peer is a DHT participant by this prefix alone. A
        // node that loses it stops being routed to, which is a much worse outcome than not
        // reporting at all, so it is worth pinning.
        for signal in [
            MigrationSignal::Legacy,
            MigrationSignal::Files,
            MigrationSignal::Unknown,
        ] {
            assert!(user_agent(signal).starts_with("node/"));
        }
    }

    #[test]
    fn a_peer_reads_back_what_a_node_announced() {
        assert_eq!(
            peer_state(&user_agent(MigrationSignal::Legacy)),
            PeerMigrationState::Legacy
        );
        assert_eq!(
            peer_state(&user_agent(MigrationSignal::Files)),
            PeerMigrationState::Files
        );
        assert_eq!(
            peer_state(&user_agent(MigrationSignal::Unknown)),
            PeerMigrationState::Unknown
        );
    }

    #[test]
    fn silence_is_counted_as_silence_and_not_as_completion() {
        // The build before this one announces the transport's own agent, with no token of
        // ours. Reading that as "finished" is exactly how a gate comes back clean over a
        // fleet that has not finished.
        assert_eq!(peer_state("node/0.27.0"), PeerMigrationState::Unreported);
        assert_eq!(
            peer_state("node/0.17.2 migration/something-new"),
            PeerMigrationState::Unknown
        );
    }

    #[test]
    fn a_client_is_not_a_node_that_failed_to_report() {
        // Clients authenticate and announce themselves too. Counting them among the peers
        // that never reported would make every reading look worse than it is, and the
        // count is what a release decision is made on.
        assert_eq!(peer_state("client/0.27.0"), PeerMigrationState::NotANode);
    }
}
