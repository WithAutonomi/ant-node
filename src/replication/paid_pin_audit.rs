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
//!      the commitment answerability TTL ([`answerability_bound_holds`],
//!      enforced at startup via [`ensure_answerability_bound`]);
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

use std::collections::{HashMap, HashSet};
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

/// Total span from a quote's signed timestamp to its confirmation deadline
/// (`MAX_AUDITED_QUOTE_AGE + MAX_FIRST_AUDIT_DELAY + CLOCK_SKEW_MARGIN`).
pub const CONFIRMATION_SPAN: Duration = Duration::from_secs((60 + 42 + 10) * 60);

/// Rule 1: the confirmation window must fit inside commitment answerability.
///
/// So a pin backing a still-live paid quote is always answerable by an honest
/// holder. See also [`ensure_answerability_bound`].
#[must_use]
pub fn answerability_bound_holds() -> bool {
    CONFIRMATION_SPAN <= GOSSIP_ANSWERABILITY_TTL
}

/// Startup guard for rule 1.
///
/// `Err` if the confirmation window would exceed commitment answerability (a
/// misconfiguration that would let a paid pin age out before its first audit,
/// reopening pay-then-shed). The node MUST refuse to start on `Err`.
///
/// # Errors
/// Returns `Err` when [`answerability_bound_holds`] is false.
pub fn ensure_answerability_bound() -> Result<(), &'static str> {
    if answerability_bound_holds() {
        Ok(())
    } else {
        Err("ADR-0004 A1: confirmation window exceeds GOSSIP_ANSWERABILITY_TTL")
    }
}

// --- The decision: provenance-scoped grading of a *definitive* miss ---------

/// Where the auditor learned a pin. Only [`PinProvenance::PaidQuote`] is eligible
/// for a confirmed (deterministic) failure; every other source keeps today's
/// grace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProvenance {
    /// Learned from an accepted client-put payment bundle, carrying the accused's
    /// signed quote (with `quote_ts`) and its signed commitment sidecar. Only
    /// admitted after [`is_admissible`] passed at ingestion.
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

/// Two-sided freshness check applied at INGESTION (admission) — the only place
/// wall-clock `now` is consulted.
///
/// A paid pin is admissible iff its signed `quote_ts` is neither older than
/// `MAX_AUDITED_QUOTE_AGE + CLOCK_SKEW_MARGIN` nor more than `CLOCK_SKEW_MARGIN`
/// in the future. Grading is then evaluation-time independent (see
/// [`grade_definitive_miss`]). Overflow/underflow of a bound is treated
/// conservatively (that bound imposes no constraint).
#[must_use]
pub fn is_admissible(quote_ts: SystemTime, now: SystemTime) -> bool {
    let not_future = now
        .checked_add(CLOCK_SKEW_MARGIN)
        .map_or(true, |upper| quote_ts <= upper);
    let not_too_old = now
        .checked_sub(MAX_AUDITED_QUOTE_AGE.saturating_add(CLOCK_SKEW_MARGIN))
        .map_or(true, |lower| quote_ts >= lower);
    not_future && not_too_old
}

/// The deadline until which an admitted paid pin is convictable on a definitive
/// miss.
///
/// Derived solely from the accused's SIGNED `quote_ts` (never the auditor's
/// clock), so grading is deterministic. `None` if the addition overflows
/// (treated as corrupt — never convict).
#[must_use]
pub fn confirmation_deadline(quote_ts: SystemTime) -> Option<SystemTime> {
    quote_ts.checked_add(CONFIRMATION_SPAN)
}

/// Grade a *definitive* miss.
///
/// `challenge_issued_at` is the auditor's own signed challenge time. Confirmed
/// iff the source is a paid quote and the challenge was issued at-or-before the
/// confirmation deadline; otherwise graced. Depends only on the signed evidence
/// (`quote_ts`, `challenge_issued_at`), not on the current clock, so a given
/// evidence bundle always grades the same. Non-response is not graded here (it
/// stays in the timeout lane).
#[must_use]
pub fn grade_definitive_miss(
    provenance: PinProvenance,
    challenge_issued_at: SystemTime,
) -> MissVerdict {
    match provenance {
        PinProvenance::PaidQuote { quote_ts } => match confirmation_deadline(quote_ts) {
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
    /// The pin (commitment hash) this record answers for. `None` only on a
    /// serialization failure that cannot occur for a well-formed commitment.
    #[must_use]
    pub fn pin(&self) -> Option<[u8; 32]> {
        commitment_hash(&self.commitment)
    }

    /// The signed quote time. `None` if `quote_ts_unix` overflows `SystemTime`
    /// (treated as corrupt — never panics).
    #[must_use]
    pub fn quote_ts(&self) -> Option<SystemTime> {
        UNIX_EPOCH.checked_add(Duration::from_secs(self.quote_ts_unix))
    }

    /// This record's confirmation deadline, or `None` if the timestamp is corrupt
    /// or overflows.
    #[must_use]
    pub fn confirmation_deadline(&self) -> Option<SystemTime> {
        self.quote_ts().and_then(confirmation_deadline)
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

/// Outcome of loading a persisted ledger, so the caller can implement the
/// required local-halt-on-corruption behavior instead of silently proceeding.
#[derive(Debug)]
pub enum LoadOutcome {
    /// The blob decoded; the ledger is the validated set (entries with an
    /// unhashable/mismatched pin were dropped).
    Loaded {
        /// The reloaded, pin-revalidated ledger.
        ledger: PaidPinLedger,
        /// Number of entries dropped because their recomputed pin was missing.
        dropped: usize,
    },
    /// The blob failed to decode. The caller MUST fail-open LOCALLY (stop issuing
    /// above-baseline quotes until rebuilt) — never a remote grace.
    Corrupt,
}

/// Restart-durable set of paid-pin obligations, keyed by pin.
///
/// Separate from the gossip retention cache. The persisted form is a plain list
/// of records; on load each pin is RECOMPUTED from its record (the persisted key
/// is never trusted), so a tampered blob cannot bind a pin to the wrong record.
#[derive(Debug, Default, Clone)]
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
    /// commitment cannot be hashed is dropped and this returns `false`.
    pub fn insert(&mut self, record: PaidPinRecord) -> bool {
        match record.pin() {
            Some(pin) => {
                self.by_pin.insert(pin, record);
                true
            }
            None => false,
        }
    }

    /// Look up the obligation for a pin.
    #[must_use]
    pub fn get(&self, pin: &[u8; 32]) -> Option<&PaidPinRecord> {
        self.by_pin.get(pin)
    }

    /// The keys held under any live paid pin — the pruner's `is_held` veto set.
    #[must_use]
    pub fn vetoed_keys(&self) -> HashSet<XorName> {
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
    ///
    /// The persisted form is the list of records (no keys). On a serialization
    /// error the caller MUST NOT overwrite the durable ledger.
    ///
    /// # Errors
    /// Propagates a `postcard` serialization error.
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        let records: Vec<&PaidPinRecord> = self.by_pin.values().collect();
        postcard::to_allocvec(&records)
    }

    /// Reload after restart, revalidating every pin.
    ///
    /// Returns [`LoadOutcome::Corrupt`] on a decode failure so the caller can
    /// fail-open locally; on success, entries whose pin cannot be recomputed are
    /// dropped and every kept entry is keyed by its recomputed pin.
    #[must_use]
    pub fn load(bytes: &[u8]) -> LoadOutcome {
        postcard::from_bytes::<Vec<PaidPinRecord>>(bytes).map_or(LoadOutcome::Corrupt, |records| {
            let mut ledger = Self::new();
            let mut dropped = 0usize;
            for r in records {
                if !ledger.insert(r) {
                    dropped += 1;
                }
            }
            LoadOutcome::Loaded { ledger, dropped }
        })
    }

    /// Drop obligations whose confirmation window has fully closed (or whose
    /// timestamp is corrupt).
    pub fn prune_expired(&mut self, now: SystemTime) {
        self.by_pin
            .retain(|_, r| r.confirmation_deadline().is_some_and(|d| now <= d));
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

    fn record(quote_ts_unix: u64) -> (PaidPinRecord, [u8; 32], Vec<(XorName, [u8; 32])>) {
        let entries: Vec<_> = (1..=5u8).map(|i| (xk(i), bh(i))).collect();
        let commitment = commitment_over(&entries);
        let pin = commitment_hash(&commitment).unwrap();
        (
            PaidPinRecord {
                commitment,
                leaf_keys: entries.iter().map(|(k, _)| *k).collect(),
                quote_ts_unix,
            },
            pin,
            entries,
        )
    }

    #[test]
    fn startup_answerability_bound_holds() {
        assert!(answerability_bound_holds());
        assert!(ensure_answerability_bound().is_ok());
        assert!(CONFIRMATION_SPAN <= GOSSIP_ANSWERABILITY_TTL);
    }

    #[test]
    fn admission_two_sided_freshness() {
        let now = SystemTime::now();
        assert!(is_admissible(now, now)); // fresh
        assert!(is_admissible(now - MAX_AUDITED_QUOTE_AGE, now)); // within age
        assert!(!is_admissible(
            now - MAX_AUDITED_QUOTE_AGE - CLOCK_SKEW_MARGIN - Duration::from_secs(60),
            now
        )); // too old
        assert!(!is_admissible(
            now + CLOCK_SKEW_MARGIN + Duration::from_secs(60),
            now
        )); // future beyond skew
    }

    #[test]
    fn grading_is_evaluation_time_independent() {
        let quote_ts = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let deadline = confirmation_deadline(quote_ts).unwrap();
        // in-window (incl exactly at the deadline) -> Confirmed
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts }, quote_ts),
            MissVerdict::Confirmed
        );
        assert_eq!(
            grade_definitive_miss(PinProvenance::PaidQuote { quote_ts }, deadline),
            MissVerdict::Confirmed
        );
        // one second past the deadline -> Graced
        assert_eq!(
            grade_definitive_miss(
                PinProvenance::PaidQuote { quote_ts },
                deadline + Duration::from_secs(1)
            ),
            MissVerdict::Graced
        );
    }

    #[test]
    fn non_paid_provenance_always_graced() {
        let t = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(
            grade_definitive_miss(PinProvenance::GossipLottery, t),
            MissVerdict::Graced
        );
        assert_eq!(
            grade_definitive_miss(PinProvenance::Receipt, t),
            MissVerdict::Graced
        );
    }

    #[test]
    fn corrupt_timestamp_never_panics_and_is_graced() {
        // u64::MAX seconds overflows SystemTime -> None deadline -> Graced, no panic.
        let (rec, _, _) = record(u64::MAX);
        assert!(rec.quote_ts().is_none());
        assert!(rec.confirmation_deadline().is_none());
    }

    #[test]
    fn ledger_survives_restart() {
        let (rec, pin, _) = record(1_800_000_000);
        let root = rec.commitment.root;
        let mut ledger = PaidPinLedger::new();
        assert!(ledger.insert(rec));
        assert_eq!(ledger.len(), 1);

        // persist -> drop -> reload == restart
        let bytes = ledger.to_bytes().unwrap();
        drop(ledger);
        let reloaded = match PaidPinLedger::load(&bytes) {
            LoadOutcome::Loaded { ledger, dropped } => {
                assert_eq!(dropped, 0);
                ledger
            }
            LoadOutcome::Corrupt => panic!("valid blob must not be Corrupt"),
        };
        let r = reloaded.get(&pin).expect("paid pin survives restart");
        assert_eq!(r.commitment.root, root);
        assert_eq!(r.leaf_keys.len(), 5);
        assert!(reloaded.vetoed_keys().contains(&xk(3)));
    }

    #[test]
    fn corrupt_blob_loads_as_corrupt_not_empty() {
        // Garbage must decode to Corrupt (so the caller can local-halt), NOT
        // silently to an empty ledger.
        assert!(matches!(
            PaidPinLedger::load(&[0xffu8; 7]),
            LoadOutcome::Corrupt
        ));
    }

    #[test]
    fn reload_rekeys_by_recomputed_pin() {
        // The persisted form carries no keys; reload rebuilds the map from
        // record.pin(), so a lookup by the true pin resolves.
        let (rec, pin, _) = record(1_800_000_000);
        let mut ledger = PaidPinLedger::new();
        ledger.insert(rec);
        let bytes = ledger.to_bytes().unwrap();
        let reloaded = match PaidPinLedger::load(&bytes) {
            LoadOutcome::Loaded { ledger, .. } => ledger,
            LoadOutcome::Corrupt => panic!("valid"),
        };
        assert!(reloaded.get(&pin).is_some());
    }

    #[test]
    fn holds_rebuilds_from_bytes_and_verifies_root() {
        let (rec, _, entries) = record(1_800_000_000);
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
        let (rec, _, _) = record(1_800_000_000);
        let mut ledger = PaidPinLedger::new();
        ledger.insert(rec);
        assert_eq!(ledger.len(), 1);
        ledger.prune_expired(base + Duration::from_secs(24 * 60 * 60));
        assert_eq!(ledger.len(), 0);
    }
}
