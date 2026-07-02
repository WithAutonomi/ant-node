//! ADR-0004 Amendment 1 — persisted, provenance-scoped paid-pin answerability.
//!
//! Design: `docs/adr/ADR-0004-commitment-bound-quote-pricing.md` (Amendment 1).
//! Implementation obligations (surfaced by adversarial review):
//! `docs/adr/ADR-0004-amendment1-implementation-notes.md`.
//!
//! Two rules close the pay-then-shed hole (get paid for a commitment, delete or
//! rotate past it, have the deterministic first audit graced as
//! `UnknownCommitment`):
//!   1. **answerability ≥ quote validity** — the confirmation window fits under
//!      the commitment answerability TTL ([`answerability_bound_holds`], asserted
//!      at startup);
//!   2. **retention survives restart** — the [`PaidPinLedger`] persists and
//!      reloads paid obligations.
//!
//! With both, a *responsive* node that returns a definitive miss
//! (`UnknownCommitment` / missing / wrong bytes) for an in-window paid pin is a
//! **confirmed** failure, not graced ([`grade_definitive_miss`]). Non-response
//! (silence / bootstrap / persistent transient) is deliberately NOT convicted
//! here — it stays in ADR-0002's existing timeout lane.
//!
//! This module is the load-bearing core; the wiring into the live audit
//! responder/grader, the pruner byte-veto, and payment verification is tracked
//! in the implementation-notes checklist.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ant_protocol::XorName;
use crate::replication::commitment::{commitment_hash, MerkleTree, StorageCommitment};
use crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;

// --- Rule 1: answerability ≥ quote validity ---------------------------------

/// Max age of a paid quote, at ingestion, for it to enter the paid-pin class.
pub const MAX_AUDITED_QUOTE_AGE: Duration = Duration::from_secs(60 * 60);

/// Upper bound on the delay from accepted payment to the deterministic first
/// audit: per-peer cooldown (30 min) + first-audit retry (≤ 5 min) + transient
/// retry budget (2 min) + scheduling slack (5 min).
pub const MAX_FIRST_AUDIT_DELAY: Duration = Duration::from_secs((30 + 5 + 2 + 5) * 60);

/// Wall-clock skew tolerance, applied to freshness admission and the
/// confirmation window.
pub const CLOCK_SKEW_MARGIN: Duration = Duration::from_secs(10 * 60);

/// Rule 1: the confirmation window must fit inside commitment answerability.
///
/// So a pin backing a still-live paid quote is always answerable by an honest
/// holder. Call at startup and refuse to boot if this returns
/// `false` (a misconfiguration would let a paid pin age out before its first
/// audit, reopening pay-then-shed).
#[must_use]
pub fn answerability_bound_holds() -> bool {
    MAX_AUDITED_QUOTE_AGE
        .saturating_add(MAX_FIRST_AUDIT_DELAY)
        .saturating_add(CLOCK_SKEW_MARGIN)
        <= GOSSIP_ANSWERABILITY_TTL
}

// --- The decision: provenance-scoped grading of a *definitive* miss ---------

/// Where the auditor learned a pin. Only [`PinProvenance::PaidQuote`] is eligible
/// for a confirmed (deterministic) failure; every other source keeps today's
/// grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProvenance {
    /// Learned from an accepted client-put payment bundle, carrying the accused's
    /// signed quote (with `quote_ts`) and its signed commitment sidecar.
    PaidQuote {
        /// The accused's own signed quote timestamp — the sole time basis for
        /// the confirmation deadline (never the auditor's clock).
        quote_ts: SystemTime,
    },
    /// Cached from gossip (no payment). Graced.
    GossipLottery,
    /// Derived from a replication receipt / aged pin. Graced.
    Receipt,
}

/// Verdict for a *definitive* audit miss (the responder answered
/// `UnknownCommitment`, or served missing/wrong bytes for a committed leaf).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissVerdict {
    /// Deterministic failure with the full trust penalty (paid, in-window,
    /// definitive).
    Confirmed,
    /// Graced timeout lane (with today's scoped credit-revocation).
    Graced,
}

/// The deadline until which a paid pin is convictable on a definitive miss.
///
/// Derived from the accused's SIGNED `quote_ts`. Returns `None` for a quote
/// dated more than [`CLOCK_SKEW_MARGIN`] in the future (never extend
/// answerability from the future — treated as corrupt/hostile).
#[must_use]
pub fn confirmation_deadline(quote_ts: SystemTime, now: SystemTime) -> Option<SystemTime> {
    if quote_ts > now + CLOCK_SKEW_MARGIN {
        return None;
    }
    Some(quote_ts + MAX_AUDITED_QUOTE_AGE + MAX_FIRST_AUDIT_DELAY + CLOCK_SKEW_MARGIN)
}

/// Grade a *definitive* miss.
///
/// `challenge_issued_at` is the auditor's own signed challenge time. Confirmed
/// iff the source is a paid quote and the challenge was
/// issued at-or-before the confirmation deadline; otherwise graced. Non-response
/// is not graded here (it stays in the timeout lane).
#[must_use]
pub fn grade_definitive_miss(
    provenance: PinProvenance,
    challenge_issued_at: SystemTime,
    now: SystemTime,
) -> MissVerdict {
    match provenance {
        PinProvenance::PaidQuote { quote_ts } => match confirmation_deadline(quote_ts, now) {
            Some(deadline) if challenge_issued_at <= deadline => MissVerdict::Confirmed,
            _ => MissVerdict::Graced,
        },
        PinProvenance::GossipLottery | PinProvenance::Receipt => MissVerdict::Graced,
    }
}

// --- Rule 2: restart-durable paid-pin ledger --------------------------------

/// One paid-pin obligation, persisted so it survives restart.
///
/// The Merkle tree is intentionally NOT stored: on audit the responder rebuilds
/// it from the still-durable chunk bytes for `leaf_keys` and verifies the root
/// against `commitment.root` — so answerability is exactly as durable as the
/// stored data. A node that still holds the data always answers; a node that
/// cannot has genuinely lost paid data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaidPinRecord {
    /// The signed commitment this record answers for.
    pub commitment: StorageCommitment,
    /// The committed leaf keys (the pruner must veto these while the record is
    /// live; the responder reads their bytes to rebuild the tree).
    pub leaf_keys: Vec<XorName>,
    /// The accused's signed quote timestamp (Unix seconds).
    pub quote_ts_unix: u64,
}

impl PaidPinRecord {
    /// The pin (commitment hash) this record answers for.
    #[must_use]
    pub fn pin(&self) -> Option<[u8; 32]> {
        commitment_hash(&self.commitment)
    }

    /// The signed quote time as a [`SystemTime`].
    #[must_use]
    pub fn quote_ts(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.quote_ts_unix)
    }

    /// Rebuild the committed tree from the CURRENT bytes-hashes of `leaf_keys`
    /// (read from durable storage) and check it matches the signed root and key
    /// count. `true` means the node still holds exactly what it committed and can
    /// answer any challenge; `false` means a committed leaf is gone or altered —
    /// a definitive miss for an honest challenge.
    #[must_use]
    pub fn holds(&self, current_bytes_hash: impl Fn(&XorName) -> Option<[u8; 32]>) -> bool {
        let mut entries = Vec::with_capacity(self.leaf_keys.len());
        for k in &self.leaf_keys {
            match current_bytes_hash(k) {
                Some(h) => entries.push((*k, h)),
                None => return false,
            }
        }
        MerkleTree::build(entries).is_ok_and(|tree| {
            tree.root() == self.commitment.root && tree.key_count() == self.commitment.key_count
        })
    }
}

/// Restart-durable set of paid-pin obligations, keyed by pin.
///
/// Separate from the gossip retention cache. Persisted (atomically; see
/// impl-notes R1d) and reloaded on startup so a restart never loses a paid
/// obligation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PaidPinLedger {
    by_pin: HashMap<[u8; 32], PaidPinRecord>,
}

impl PaidPinLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a paid-pin obligation (idempotent per pin). A record whose
    /// commitment cannot be hashed is dropped.
    pub fn insert(&mut self, record: PaidPinRecord) {
        if let Some(pin) = record.pin() {
            self.by_pin.insert(pin, record);
        }
    }

    /// Look up the obligation for a pin.
    #[must_use]
    pub fn get(&self, pin: &[u8; 32]) -> Option<&PaidPinRecord> {
        self.by_pin.get(pin)
    }

    /// The keys held under any live paid pin — the pruner's `is_held` veto set.
    #[must_use]
    pub fn vetoed_keys(&self) -> std::collections::HashSet<XorName> {
        self.by_pin
            .values()
            .flat_map(|r| r.leaf_keys.iter().copied())
            .collect()
    }

    /// Number of live paid-pin obligations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_pin.len()
    }

    /// Whether the ledger holds no obligations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_pin.is_empty()
    }

    /// Serialize for durable persistence (caller writes it atomically).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Reload after restart. A corrupt blob yields an empty ledger: fail-open
    /// *locally* — the node stops issuing above-baseline quotes until rebuilt —
    /// which never grants a remote grace (a remote auditor still convicts an
    /// in-window definitive miss).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        postcard::from_bytes(bytes).unwrap_or_default()
    }

    /// Drop obligations whose confirmation window has fully closed.
    pub fn prune_expired(&mut self, now: SystemTime) {
        self.by_pin
            .retain(|_, r| confirmation_deadline(r.quote_ts(), now).is_some_and(|d| now <= d));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn xk(b: u8) -> XorName {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }
    fn bh(b: u8) -> [u8; 32] {
        [b ^ 0x5A; 32]
    }

    /// A `StorageCommitment` with a REAL Merkle root over `entries` (a dummy
    /// signature — the pin/hash/persistence/root-verification never check it).
    fn commitment_over(entries: &[(XorName, [u8; 32])]) -> StorageCommitment {
        let tree = MerkleTree::build(entries.to_vec()).unwrap();
        StorageCommitment {
            root: tree.root(),
            key_count: tree.key_count(),
            sender_peer_id: [7u8; 32],
            sender_public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        }
    }

    #[test]
    fn startup_answerability_bound_holds() {
        // Rule 1: refuse to boot if the confirmation window exceeds the TTL.
        assert!(
            answerability_bound_holds(),
            "confirmation window ({:?}) must fit under GOSSIP_ANSWERABILITY_TTL ({:?})",
            MAX_AUDITED_QUOTE_AGE + MAX_FIRST_AUDIT_DELAY + CLOCK_SKEW_MARGIN,
            GOSSIP_ANSWERABILITY_TTL
        );
    }

    #[test]
    fn in_window_paid_definitive_miss_is_confirmed() {
        let now = SystemTime::now();
        // Fresh paid quote, audited immediately -> confirmed.
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts: now }, now, now),
            MissVerdict::Confirmed
        );
        // Audited after the full 30-min cooldown (still inside the window) ->
        // still confirmed (the two-window fix: cooldown delay does not grace).
        let later = now + MAX_AUDITED_QUOTE_AGE + MAX_FIRST_AUDIT_DELAY;
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts: now }, later, later),
            MissVerdict::Confirmed
        );
    }

    #[test]
    fn out_of_window_paid_miss_is_graced() {
        let now = SystemTime::now();
        let late = now
            + MAX_AUDITED_QUOTE_AGE
            + MAX_FIRST_AUDIT_DELAY
            + CLOCK_SKEW_MARGIN
            + Duration::from_secs(60);
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts: now }, late, late),
            MissVerdict::Graced
        );
    }

    #[test]
    fn gossip_receipt_and_future_quote_are_graced() {
        let now = SystemTime::now();
        assert_eq!(
            grade_definitive_miss(PinProvenance::GossipLottery, now, now),
            MissVerdict::Graced
        );
        assert_eq!(
            grade_definitive_miss(PinProvenance::Receipt, now, now),
            MissVerdict::Graced
        );
        // A future-dated quote beyond skew yields no deadline -> graced (cannot
        // push the window out).
        let future = now + CLOCK_SKEW_MARGIN + Duration::from_secs(3600);
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts: future }, now, now),
            MissVerdict::Graced
        );
    }

    #[test]
    fn ledger_survives_restart() {
        // Rule 2: a paid obligation persists across a simulated restart.
        let entries: Vec<_> = (1..=5u8).map(|i| (xk(i), bh(i))).collect();
        let commitment = commitment_over(&entries);
        let pin = commitment_hash(&commitment).unwrap();

        let mut ledger = PaidPinLedger::new();
        ledger.insert(PaidPinRecord {
            commitment: commitment.clone(),
            leaf_keys: entries.iter().map(|(k, _)| *k).collect(),
            quote_ts_unix: 1_800_000_000,
        });
        assert_eq!(ledger.len(), 1);

        // persist -> drop -> reload == restart
        let bytes = ledger.to_bytes();
        drop(ledger);
        let reloaded = PaidPinLedger::from_bytes(&bytes);

        let rec = reloaded
            .get(&pin)
            .expect("paid pin must be answerable after restart");
        assert_eq!(rec.commitment.root, commitment.root);
        assert_eq!(rec.leaf_keys.len(), 5);
        assert!(reloaded.vetoed_keys().contains(&xk(3)));
    }

    #[test]
    fn holds_rebuilds_from_bytes_and_verifies_root() {
        // answerability == data durability: reload rebuilds the tree from the
        // durable chunk bytes and checks the signed root.
        let entries: Vec<_> = (1..=5u8).map(|i| (xk(i), bh(i))).collect();
        let rec = PaidPinRecord {
            commitment: commitment_over(&entries),
            leaf_keys: entries.iter().map(|(k, _)| *k).collect(),
            quote_ts_unix: 1_800_000_000,
        };
        let store: HashMap<XorName, [u8; 32]> = entries.iter().copied().collect();

        // Honest holder: all bytes present and unchanged -> can answer.
        assert!(rec.holds(|k| store.get(k).copied()));

        // Deleter: a committed leaf's bytes are gone -> definitive miss.
        let mut deleted = store.clone();
        deleted.remove(&xk(3));
        assert!(!rec.holds(|k| deleted.get(k).copied()));

        // Tamperer: a committed leaf's bytes changed -> root mismatch -> miss.
        let mut tampered = store.clone();
        tampered.insert(xk(3), [0xFFu8; 32]);
        assert!(!rec.holds(|k| tampered.get(k).copied()));
    }

    #[test]
    fn prune_expired_drops_closed_windows() {
        let base = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let entries: Vec<_> = (1..=3u8).map(|i| (xk(i), bh(i))).collect();
        let mut ledger = PaidPinLedger::new();
        ledger.insert(PaidPinRecord {
            commitment: commitment_over(&entries),
            leaf_keys: entries.iter().map(|(k, _)| *k).collect(),
            quote_ts_unix: 1_800_000_000,
        });
        assert_eq!(ledger.len(), 1);
        // Well past the confirmation window -> pruned.
        ledger.prune_expired(base + Duration::from_secs(24 * 60 * 60));
        assert_eq!(ledger.len(), 0);
    }
}
