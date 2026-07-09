//! Per-peer audit tally — the node-side standing record for ADR-0005.
//!
//! Every subtree (commitment) audit outcome this node observes is remembered
//! here as plain counts: passes per day and the largest committed key count
//! that passed, plus two row-local markers — a deterministic conviction (zeroes
//! the row and stays sticky for one dues period) and an unanswered challenge on
//! a pin the peer monetized (fences the row until a fresh pass clears it).
//! Nothing is weighted, decayed, or tuned; the client aggregates a majority of
//! these rows into the eligibility decision.
//!
//! Only the *subtree* audit lane feeds the tally: its passes carry the audited
//! commitment's key count (the "at this size" half of the dues) and its
//! confirmed failures are deterministic convictions. The responsible-chunk
//! audit lane stays out — its timeouts are not deterministic and its passes
//! carry no committed size.
//!
//! Two codecs, do not confuse them: the on-disk SNAPSHOT here uses **postcard**
//! ([`AuditTally::from_bytes`]/[`AuditTally::snapshot_bytes`], mirroring
//! `commitment_retention.bin`, ADR-0004 A1 — write-on-change, atomic temp-file
//! rename); the WIRE report shipped on a quote response is **`MessagePack`**
//! (`rmp_serde`, built in `payment::quote::build_audit_report`). Losing the
//! snapshot only costs this observer's testimony window — the subject re-earns
//! it through ordinary audits.

use std::collections::HashMap;

use crate::logging::warn;
use saorsa_core::identity::PeerId;
use serde::{Deserialize, Serialize};

use ant_protocol::payment::{AuditReportDay, AuditReportRow, MAX_REPORT_DAYS, MAX_REPORT_ROWS};

/// Tally window, in day buckets. Day entries older than this are pruned.
pub const TALLY_WINDOW_DAYS: u64 = 14;

/// How long a conviction marker stays sticky (ADR-0005 v4): one dues period.
///
/// A pass does NOT clear it — each observer that catches a peer withholds its
/// vouch for a full re-grind, so partial catches bite under the relative bar.
pub const CONVICTION_STICKY_DAYS: u64 = 7;

/// Cap on tracked rows. The neighbour-sync observation scope is ~20 peers, so
/// this leaves generous slack; when full, the stalest row is evicted.
pub const MAX_TALLY_ROWS: usize = 64;

/// Current unix time in whole seconds.
///
/// 0 only if the system clock is before the epoch (never panics — tally
/// timestamps degrade, nothing else).
#[must_use]
pub fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Length of one tally day bucket in seconds.
#[must_use]
pub fn tally_day_secs() -> u64 {
    86_400
}

/// One day bucket of outcomes for one observed peer.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
struct DayCell {
    /// Subtree audit passes recorded in this bucket.
    passes: u32,
    /// Largest committed key count that passed in this bucket.
    max_passed_key_count: u32,
}

/// The tally row for one observed peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct TallyRow {
    /// Day-index → outcomes. Day index = `unix_secs / tally_day_secs()`.
    days: Vec<(u64, DayCell)>,
    /// Day index of the last deterministic conviction, if any. Sticky for
    /// [`CONVICTION_STICKY_DAYS`]; passes do NOT clear it.
    convicted_day: Option<u64>,
    /// Day index the row was fenced by an unanswered monetized-pin challenge,
    /// if outstanding. Cleared by the next recorded pass. Also aged out in
    /// [`TallyRow::prune`] once the window has fully passed AND no day-evidence
    /// remains: an eternal fence with no underlying passes would outlast the
    /// evidence it was meant to freeze, so it is bounded to the window.
    fenced_day: Option<u64>,
    /// Day index of the most recent activity, for row eviction.
    last_touched_day: u64,
}

impl TallyRow {
    fn prune(&mut self, today: u64) {
        self.days
            .retain(|(day, _)| today.saturating_sub(*day) < TALLY_WINDOW_DAYS);
        if let Some(day) = self.convicted_day {
            if today.saturating_sub(day) >= CONVICTION_STICKY_DAYS {
                self.convicted_day = None;
            }
        }
        // Age out a fence that has outlasted the window with no day-evidence
        // left underneath it. The fence normally clears on the peer's next
        // pass; but a peer that goes silent forever would otherwise keep this
        // observer's row fenced indefinitely — longer than the evidence it
        // froze. Once the window has fully passed AND no pass days remain,
        // there is nothing left to freeze, so drop the fence (the row then
        // ages out via `is_empty`).
        if let Some(day) = self.fenced_day {
            if self.days.is_empty() && today.saturating_sub(day) >= TALLY_WINDOW_DAYS {
                self.fenced_day = None;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.days.is_empty() && self.convicted_day.is_none() && self.fenced_day.is_none()
    }
}

/// Snapshot format tag: magic + version, prepended to the postcard body.
///
/// Postcard is non-self-describing and decodes positionally, so a struct-layout
/// change (e.g. the v5 `fenced`/`convicted` `bool` → `Option<u64>` retype) makes
/// an older on-disk blob mis-decode into garbage rather than fail cleanly. The
/// tag turns that into a deliberate, safe rejection: [`AuditTally::from_bytes`]
/// discards any snapshot whose tag it does not recognise and the observer starts
/// fresh — cheap, since a lost snapshot only costs this observer's testimony
/// window, which it re-earns through ordinary audits. Bump [`SNAPSHOT_VERSION`]
/// on any change to the serialized layout of `AuditTally` or its fields.
const SNAPSHOT_MAGIC: &[u8; 4] = b"ATLY";
const SNAPSHOT_VERSION: u8 = 1;

/// The audit tally: per-peer rows of subtree-audit outcomes.
///
/// Interior state only — callers wrap it in their own lock and drive
/// persistence with [`AuditTally::snapshot_bytes`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AuditTally {
    rows: HashMap<PeerId, TallyRow>,
}

impl AuditTally {
    /// Restore from persisted snapshot bytes; `None` if the tag is unrecognised
    /// (wrong magic or an older/newer layout version) or the body is corrupt.
    /// An unrecognised snapshot is discarded rather than mis-decoded, so the
    /// observer safely starts fresh across a format change.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let body = bytes
            .strip_prefix(SNAPSHOT_MAGIC.as_slice())
            .and_then(|rest| rest.split_first())
            .filter(|(version, _)| **version == SNAPSHOT_VERSION)
            .map(|(_, body)| body)?;
        postcard::from_bytes(body).ok()
    }

    /// Snapshot for persistence: the format tag followed by the postcard body.
    /// `None` only on serialization failure.
    #[must_use]
    pub fn snapshot_bytes(&self) -> Option<Vec<u8>> {
        let body = postcard::to_allocvec(self).ok()?;
        let mut out = Vec::with_capacity(SNAPSHOT_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(SNAPSHOT_MAGIC.as_slice());
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Record a subtree audit pass for `peer` on a commitment of
    /// `commitment_key_count` keys. Clears any fence. Does NOT clear an
    /// outstanding conviction (ADR-0005 v4): the marker stays sticky for
    /// [`CONVICTION_STICKY_DAYS`], so a catch costs this observer's vouch for
    /// a full dues period while the zeroed history re-accumulates underneath.
    ///
    /// # Precondition (event ordering)
    ///
    /// `now_secs` MUST be the observer's real-time clock at the moment the audit
    /// outcome is processed — never a timestamp carried on the wire. All three
    /// record paths pass [`unix_now_secs`], so events are stamped in processing
    /// order and `now_secs` is monotonic non-decreasing. This is what makes
    /// "a pass clears the fence" safe: a pass can only clear a fence that was set
    /// at or before the same wall-clock instant, so an out-of-order/replayed
    /// pass cannot retroactively lift a newer fence. Do not feed this a
    /// caller-supplied or attacker-influenced timestamp.
    pub fn record_pass(&mut self, peer: PeerId, commitment_key_count: u32, now_secs: u64) {
        let today = now_secs / tally_day_secs();
        self.evict_if_full(&peer, today);
        let row = self.rows.entry(peer).or_default();
        row.prune(today);
        row.fenced_day = None;
        row.last_touched_day = today;
        match row.days.iter_mut().find(|(day, _)| *day == today) {
            Some((_, cell)) => {
                cell.passes = cell.passes.saturating_add(1);
                cell.max_passed_key_count = cell.max_passed_key_count.max(commitment_key_count);
            }
            None => {
                row.days.push((
                    today,
                    DayCell {
                        passes: 1,
                        max_passed_key_count: commitment_key_count,
                    },
                ));
            }
        }
    }

    /// Record a deterministic conviction: the row is zeroed — the peer starts
    /// its dues over in this observer's eyes — and the marker stays sticky for
    /// [`CONVICTION_STICKY_DAYS`] regardless of new passes. Stickiness equals
    /// the dues period, so the total cost of a catch is one full re-grind at
    /// this observer; it can never compound into a permanent ban.
    ///
    /// Clearing `fenced_day` here is intentional, not a weakening: a conviction
    /// strictly subsumes a fence. A convicted row does not vouch at all (the
    /// client checks `convicted` independently), and the conviction's stickiness
    /// covers the full dues period — longer than any fence would have lasted. On
    /// expiry the peer must re-earn its entire week regardless. Keeping a
    /// now-redundant fence marker alongside the conviction would buy no extra
    /// suppression and only complicate the age-out invariant.
    pub fn record_conviction(&mut self, peer: PeerId, now_secs: u64) {
        let today = now_secs / tally_day_secs();
        self.evict_if_full(&peer, today);
        let row = self.rows.entry(peer).or_default();
        row.days.clear();
        row.fenced_day = None;
        row.convicted_day = Some(today);
        row.last_touched_day = today;
    }

    /// Record an unanswered audit challenge on a pin the peer monetized: the
    /// row is fenced (its testimony stops counting) until the next pass.
    pub fn record_unanswered_monetized_challenge(&mut self, peer: PeerId, now_secs: u64) {
        let today = now_secs / tally_day_secs();
        self.evict_if_full(&peer, today);
        let row = self.rows.entry(peer).or_default();
        row.fenced_day = Some(today);
        row.last_touched_day = today;
    }

    /// Build wire report rows as of `now_secs`: prune the window, convert day
    /// indexes to relative ages, and cap rows/days to the wire limits (rows
    /// with the most recent activity win the cap).
    #[must_use]
    pub fn report_rows(&mut self, now_secs: u64) -> Vec<AuditReportRow> {
        let today = now_secs / tally_day_secs();
        self.rows.retain(|_, row| {
            row.prune(today);
            !row.is_empty()
        });
        let mut rows: Vec<(&PeerId, &TallyRow)> = self.rows.iter().collect();
        rows.sort_by_key(|(_, row)| std::cmp::Reverse(row.last_touched_day));
        rows.truncate(MAX_REPORT_ROWS);
        rows.into_iter()
            .map(|(peer, row)| {
                let mut days: Vec<AuditReportDay> = row
                    .days
                    .iter()
                    .map(|(day, cell)| AuditReportDay {
                        age_days: u16::try_from(today.saturating_sub(*day)).unwrap_or(u16::MAX),
                        passes: cell.passes,
                        max_passed_key_count: cell.max_passed_key_count,
                    })
                    .collect();
                days.sort_by_key(|d| d.age_days);
                days.truncate(MAX_REPORT_DAYS);
                AuditReportRow {
                    subject_peer_id: *peer.as_bytes(),
                    days,
                    fenced: row.fenced_day.is_some(),
                    convicted: row.convicted_day.is_some(),
                }
            })
            .collect()
    }

    /// Number of tracked rows (diagnostics/tests).
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Evict the stalest row when at capacity and `peer` is not yet tracked.
    fn evict_if_full(&mut self, peer: &PeerId, today: u64) {
        if self.rows.len() < MAX_TALLY_ROWS || self.rows.contains_key(peer) {
            return;
        }
        // Prefer dropping rows that fell out of the window entirely.
        self.rows.retain(|_, row| {
            row.prune(today);
            !row.is_empty()
        });
        if self.rows.len() < MAX_TALLY_ROWS {
            return;
        }
        if let Some(stalest) = self
            .rows
            .iter()
            .min_by_key(|(_, row)| row.last_touched_day)
            .map(|(p, _)| *p)
        {
            self.rows.remove(&stalest);
        }
    }
}

/// Adapter exposing an [`AuditTally`] as the quote generator's
/// [`crate::payment::quote::AuditReportSource`] (ADR-0005 assembly glue).
pub struct TallyReportSource {
    tally: std::sync::Arc<std::sync::RwLock<AuditTally>>,
    reporter_peer_id: [u8; 32],
}

impl TallyReportSource {
    /// Bundle the engine's tally handle with this node's own peer id.
    #[must_use]
    pub fn new(
        tally: std::sync::Arc<std::sync::RwLock<AuditTally>>,
        reporter_peer_id: [u8; 32],
    ) -> Self {
        Self {
            tally,
            reporter_peer_id,
        }
    }
}

impl crate::payment::quote::AuditReportSource for TallyReportSource {
    fn reporter_peer_id(&self) -> [u8; 32] {
        self.reporter_peer_id
    }

    fn report_rows(&self) -> Vec<AuditReportRow> {
        self.tally.write().map_or_else(
            |_| {
                // A poisoned lock means a writer panicked mid-update. Say so
                // loudly: "no testimony" must be distinguishable from
                // "tally disabled by poison".
                warn!("Audit tally lock poisoned — reporting no rows until restart");
                Vec::new()
            },
            |mut tally| tally.report_rows(unix_now_secs()),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    #[test]
    fn passes_accumulate_per_day_with_max_size() {
        let mut t = AuditTally::default();
        t.record_pass(peer(1), 100, 10 * DAY + 5);
        t.record_pass(peer(1), 900, 10 * DAY + 600);
        t.record_pass(peer(1), 300, 11 * DAY);
        let rows = t.report_rows(11 * DAY + 1);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.subject_peer_id, [1u8; 32]);
        assert_eq!(row.days.len(), 2);
        // Newest first: today (age 0) then yesterday (age 1).
        let [d0, d1] = &row.days[..] else {
            panic!("expected two days, got {}", row.days.len());
        };
        assert_eq!(d0.age_days, 0);
        assert_eq!(d0.passes, 1);
        assert_eq!(d0.max_passed_key_count, 300);
        assert_eq!(d1.age_days, 1);
        assert_eq!(d1.passes, 2);
        assert_eq!(d1.max_passed_key_count, 900);
        assert!(!row.fenced);
        assert!(!row.convicted);
    }

    #[test]
    fn conviction_zeroes_history_and_stays_sticky_for_dues_period() {
        let mut t = AuditTally::default();
        for d in 0..7 {
            t.record_pass(peer(2), 500, d * DAY + 1);
        }
        t.record_conviction(peer(2), 7 * DAY);
        let rows = t.report_rows(7 * DAY + 1);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].days.is_empty(), "conviction must zero the history");
        assert!(rows[0].convicted, "outstanding conviction is reported");
        // v4: passes do NOT clear the marker — it stays for a full dues
        // period while the fresh history re-accumulates underneath.
        for d in 8..14 {
            t.record_pass(peer(2), 500, d * DAY);
        }
        let rows = t.report_rows(13 * DAY + 1);
        assert!(!rows[0].days.is_empty(), "history re-accumulates");
        assert!(
            rows[0].convicted,
            "the marker survives passes inside the sticky period"
        );
        // After CONVICTION_STICKY_DAYS the marker expires; the re-earned
        // history stands on its own.
        t.record_pass(peer(2), 500, (7 + CONVICTION_STICKY_DAYS) * DAY + 1);
        let rows = t.report_rows((7 + CONVICTION_STICKY_DAYS) * DAY + 2);
        assert!(
            !rows[0].convicted,
            "the marker expires after one dues period"
        );
        assert!(
            !rows[0].days.is_empty(),
            "re-earned days survive the expiry"
        );
    }

    #[test]
    fn conviction_row_without_passes_expires_with_the_sticky_period() {
        let mut t = AuditTally::default();
        t.record_conviction(peer(3), 0);
        let rows = t.report_rows(1);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].convicted);
        // Never re-proves anything: the marker (and the empty row) age out
        // after the sticky period.
        let rows = t.report_rows(CONVICTION_STICKY_DAYS * DAY + 1);
        assert!(rows.is_empty(), "an abandoned convicted row expires");
    }

    #[test]
    fn fence_blocks_until_next_pass() {
        let mut t = AuditTally::default();
        t.record_pass(peer(4), 500, DAY);
        t.record_unanswered_monetized_challenge(peer(4), DAY + 10);
        let rows = t.report_rows(DAY + 20);
        let row = rows.first().expect("one row");
        assert!(row.fenced);
        assert_eq!(row.days.len(), 1, "fence keeps history, blocks it");
        t.record_pass(peer(4), 500, DAY + 30);
        let rows = t.report_rows(DAY + 40);
        assert!(
            !rows.first().expect("one row").fenced,
            "a fresh pass clears the fence"
        );
    }

    #[test]
    fn fence_ages_out_after_window_with_no_evidence() {
        // A peer that goes silent forever after a monetized-pin timeout: no
        // fresh pass ever clears the fence, but once the window passes and no
        // day-evidence remains, the fence (and the row) age out — an eternal
        // fence would outlast the evidence it froze.
        let mut t = AuditTally::default();
        t.record_pass(peer(5), 500, DAY);
        t.record_unanswered_monetized_challenge(peer(5), 2 * DAY);
        // Still fenced within the window (day-evidence at day 1 still present).
        assert!(
            t.report_rows(3 * DAY).first().expect("row").fenced,
            "fence holds while evidence is in-window"
        );
        // Well past the window: day-1 pass pruned, fence has nothing to freeze.
        let rows = t.report_rows((TALLY_WINDOW_DAYS + 3) * DAY);
        assert!(
            rows.is_empty(),
            "an eternal fence with no evidence ages out with the row"
        );
    }

    #[test]
    fn old_days_prune_out_of_the_window() {
        let mut t = AuditTally::default();
        t.record_pass(peer(5), 500, 0);
        t.record_pass(peer(5), 500, (TALLY_WINDOW_DAYS - 1) * DAY);
        let rows = t.report_rows(TALLY_WINDOW_DAYS * DAY);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].days.len(),
            1,
            "the day-0 bucket must have pruned out"
        );
    }

    #[test]
    fn snapshot_roundtrip_preserves_rows() {
        let mut t = AuditTally::default();
        t.record_pass(peer(6), 123, 5 * DAY);
        t.record_unanswered_monetized_challenge(peer(7), 5 * DAY);
        let bytes = t.snapshot_bytes().unwrap();
        let mut restored = AuditTally::from_bytes(&bytes).unwrap();
        assert_eq!(restored.row_count(), 2);
        let rows = restored.report_rows(5 * DAY + 1);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn corrupt_snapshot_returns_none() {
        assert!(AuditTally::from_bytes(&[0xFF, 0x00, 0x13, 0x37]).is_none());
    }

    #[test]
    fn snapshot_tag_rejects_untagged_and_wrong_version() {
        let mut t = AuditTally::default();
        t.record_pass(peer(6), 123, 5 * DAY);
        let tagged = t.snapshot_bytes().unwrap();

        // A raw postcard body with NO tag (what an older format wrote) must be
        // rejected — mis-decoding it into garbage is exactly what the tag
        // prevents.
        let untagged = postcard::to_allocvec(&t).unwrap();
        assert!(AuditTally::from_bytes(&untagged).is_none());

        // Right magic, wrong version → rejected.
        let mut wrong_version = tagged.clone();
        wrong_version[SNAPSHOT_MAGIC.len()] = SNAPSHOT_VERSION.wrapping_add(1);
        assert!(AuditTally::from_bytes(&wrong_version).is_none());

        // Wrong magic → rejected.
        let mut wrong_magic = tagged.clone();
        wrong_magic[0] ^= 0xFF;
        assert!(AuditTally::from_bytes(&wrong_magic).is_none());

        // The correctly tagged snapshot still round-trips.
        assert!(AuditTally::from_bytes(&tagged).is_some());
    }

    #[test]
    fn row_cap_evicts_when_full() {
        let mut t = AuditTally::default();
        let base = 100 * DAY;
        for i in 0..MAX_TALLY_ROWS {
            let mut id = [u8::try_from(i % 250).unwrap(); 32];
            id[0] = u8::try_from(i / 250).unwrap();
            t.record_pass(PeerId::from_bytes(id), 1, base + u64::try_from(i).unwrap());
        }
        assert_eq!(t.row_count(), MAX_TALLY_ROWS);
        t.record_pass(peer(255), 1, base + 999);
        assert_eq!(t.row_count(), MAX_TALLY_ROWS, "cap holds under insert");
    }
}
