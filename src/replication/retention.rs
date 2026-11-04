//! Pressure-gated retention (ADR-0028).
//!
//! A node keeps every record it holds while its disk has room, including the
//! records it is no longer responsible for, and goes on serving them. Leaving
//! a record's range only makes the record *eligible* to be erased. The prune
//! passes erase eligible records only while the partition holding the record
//! store is under pressure: farthest from this node first, each after its
//! current close group proves possession, and only until the pressure ends.
//!
//! This module holds the policy both prune passes share: when the partition
//! is under pressure, with hysteresis so a node erases in spells rather than
//! one record at a time, and in what order eligible records go.

use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use saorsa_core::identity::PeerId;

use crate::ant_protocol::XorName;
use crate::client::xor_distance;
use crate::storage::{ChunkStore, DiskSpace};

/// Denominator of the free-space shares below.
const PERCENT: u128 = 100;

/// Free share of the partition, in percent, below which pressure starts.
const PRESSURE_ENTER_FREE_PERCENT: u128 = 10;

/// Free share, in percent, at or above which pressure ends.
///
/// Above the entry share, so a node that starts erasing frees a margin before
/// it stops, instead of erasing one record each time a write takes it back
/// under the line.
const PRESSURE_EXIT_FREE_PERCENT: u128 = 15;

/// Multiple of the store's reserve below which pressure starts, whatever the
/// free share.
///
/// On a small partition the free share can stay above
/// [`PRESSURE_ENTER_FREE_PERCENT`] until the store refuses writes at its
/// reserve. This starts erasing while there is still room above the reserve.
const PRESSURE_ENTER_RESERVE_MULTIPLE: u64 = 2;

/// Multiple of the store's reserve that must be free, as well as
/// [`PRESSURE_EXIT_FREE_PERCENT`], for pressure to end.
const PRESSURE_EXIT_RESERVE_MULTIPLE: u64 = 3;

/// Which store a record lives in.
///
/// Demotions are kept per kind: a chunk and a pointer may share an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// A content-addressed chunk.
    Chunk,
    /// A pointer record.
    Pointer,
}

/// Disk-pressure state shared by a node's chunk and pointer prune passes.
#[derive(Debug, Default)]
pub struct DiskPressure {
    state: Mutex<PressureState>,
}

#[derive(Debug, Default)]
struct PressureState {
    /// Whether the partition is under pressure.
    active: bool,
    /// Per kind, the records whose possession check failed in this spell of
    /// pressure, each with when it last failed, as a count of demotions. They
    /// are tried after every other eligible record, oldest failure first, so
    /// records nobody can prove yet never keep the rest from their turn.
    demoted: HashMap<RecordKind, HashMap<XorName, u64>>,
    /// How many demotions this node has recorded.
    demotions: u64,
    /// When the last prune pass finished.
    last_pass: Option<Instant>,
}

impl DiskPressure {
    /// Update the state from a fresh measurement, and say whether the node may
    /// erase eligible records now.
    ///
    /// A failed measurement (`None`) says nothing about free space: nothing is
    /// erased on it, and the state is left for the next measurement to decide.
    /// A spell of pressure that ends forgets its demotions.
    pub fn observe(&self, space: Option<DiskSpace>, reserve: u64) -> bool {
        let Some(space) = space else {
            return false;
        };
        let mut state = self.state.lock();
        let active = under_pressure(state.active, space, reserve);
        if state.active && !active {
            state.demoted.clear();
        }
        state.active = active;
        active
    }

    /// Measure `store`'s partition afresh and [`Self::observe`] it.
    ///
    /// Some filesystems show freed space only after a later commit, so a pass
    /// may erase a little past the exit line. That is bounded by one pass's
    /// budget, and costs only out-of-range records the group has proven.
    pub fn observe_store(&self, store: &ChunkStore) -> bool {
        self.observe(store.disk_space(), store.disk_reserve())
    }

    /// Whether a prune pass should run now.
    ///
    /// A pass runs after every completed neighbour-sync cycle. Under pressure
    /// it also runs on other rounds, `spacing` after the last pass finished:
    /// rounds run back to back while newly close peers are synced, and each
    /// pass scans every stored record.
    pub fn prune_pass_due(
        &self,
        cycle_complete: bool,
        store: &ChunkStore,
        spacing: Duration,
    ) -> bool {
        let under_pressure = !cycle_complete && self.observe_store(store);
        self.pass_due_at(cycle_complete, under_pressure, spacing, Instant::now())
    }

    fn pass_due_at(
        &self,
        cycle_complete: bool,
        under_pressure: bool,
        spacing: Duration,
        now: Instant,
    ) -> bool {
        let spaced = self
            .state
            .lock()
            .last_pass
            .is_none_or(|last| now.saturating_duration_since(last) >= spacing);
        cycle_complete || (under_pressure && spaced)
    }

    /// Record that a prune pass has finished, so the next one is spaced from it.
    pub fn prune_pass_finished(&self) {
        self.finish_pass_at(Instant::now());
    }

    fn finish_pass_at(&self, now: Instant) {
        self.state.lock().last_pass = Some(now);
    }

    /// Record that `key`'s possession check failed in this spell of pressure,
    /// so it is tried after the other eligible records, and after the records
    /// that failed before it.
    ///
    /// Ignored outside a spell, which has no order to change.
    pub fn demote(&self, kind: RecordKind, key: XorName) {
        let mut state = self.state.lock();
        if state.active {
            let failure = state.demotions;
            state.demotions = failure.saturating_add(1);
            state.demoted.entry(kind).or_default().insert(key, failure);
        }
    }

    /// The first `limit` of `records` in the order to try erasing them:
    /// records not demoted, farthest from `self_id` first, then demoted ones,
    /// oldest failure first.
    ///
    /// Farthest first, so the records closest to this node go last. Oldest
    /// failure first,
    /// so a record that failed once for a passing reason gets another turn
    /// within the spell, however many new candidates arrive. Demotions of
    /// records that are no longer candidates are forgotten.
    pub fn erasure_order<T>(
        &self,
        kind: RecordKind,
        self_id: &PeerId,
        mut records: Vec<T>,
        limit: usize,
        key_of: impl Fn(&T) -> XorName,
    ) -> Vec<T> {
        let candidates: HashSet<XorName> = records.iter().map(&key_of).collect();
        let demoted = self.current_demotions(kind, &candidates);
        let self_xor: XorName = *self_id.as_bytes();
        let order_key = |record: &T| {
            let key = key_of(record);
            (
                // `None` sorts first, so records not demoted go first.
                demoted.get(&key).copied(),
                Reverse(xor_distance(&self_xor, &key)),
            )
        };
        if limit == 0 {
            return Vec::new();
        }
        if limit < records.len() {
            records.select_nth_unstable_by_key(limit - 1, &order_key);
            records.truncate(limit);
        }
        records.sort_by_key(order_key);
        records
    }

    /// The demotions of `kind` that still apply to `candidates`.
    fn current_demotions(
        &self,
        kind: RecordKind,
        candidates: &HashSet<XorName>,
    ) -> HashMap<XorName, u64> {
        let mut state = self.state.lock();
        let demoted = state.demoted.entry(kind).or_default();
        demoted.retain(|key, _| candidates.contains(key));
        demoted.clone()
    }
}

/// Whether the partition is under pressure, given whether it already was.
fn under_pressure(was_active: bool, space: DiskSpace, reserve: u64) -> bool {
    let free_share_below =
        |percent: u128| u128::from(space.available) * PERCENT < u128::from(space.total) * percent;
    if was_active {
        free_share_below(PRESSURE_EXIT_FREE_PERCENT)
            || space.available < reserve.saturating_mul(PRESSURE_EXIT_RESERVE_MULTIPLE)
    } else {
        free_share_below(PRESSURE_ENTER_FREE_PERCENT)
            || space.available < reserve.saturating_mul(PRESSURE_ENTER_RESERVE_MULTIPLE)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TOTAL: u64 = 1_000_000;
    const NO_RESERVE: u64 = 0;
    const NO_LIMIT: usize = usize::MAX;

    fn space(available: u64) -> DiskSpace {
        DiskSpace {
            available,
            total: TOTAL,
        }
    }

    fn key(first: u8) -> XorName {
        let mut key = [0u8; 32];
        key[0] = first;
        key
    }

    fn self_id() -> PeerId {
        PeerId::from_bytes([0u8; 32])
    }

    fn under_pressure_now() -> DiskPressure {
        let pressure = DiskPressure::default();
        assert!(pressure.observe(Some(space(0)), NO_RESERVE));
        pressure
    }

    #[test]
    fn pressure_starts_below_ten_percent_free_and_ends_at_fifteen() {
        let pressure = DiskPressure::default();
        assert!(
            !pressure.observe(Some(space(100_000)), NO_RESERVE),
            "10% free is not pressure"
        );
        assert!(
            pressure.observe(Some(space(99_999)), NO_RESERVE),
            "below 10% free is"
        );
        assert!(
            pressure.observe(Some(space(149_999)), NO_RESERVE),
            "pressure holds until 15% is free"
        );
        assert!(
            !pressure.observe(Some(space(150_000)), NO_RESERVE),
            "15% free ends it"
        );
        assert!(
            !pressure.observe(Some(space(120_000)), NO_RESERVE),
            "between the lines, a node not under pressure stays out of it"
        );
    }

    #[test]
    fn a_small_partition_comes_under_pressure_before_its_reserve() {
        const RESERVE: u64 = 300_000;
        let pressure = DiskPressure::default();
        // 50% free is far above the free-share line, but under twice the reserve.
        assert!(pressure.observe(Some(space(500_000)), RESERVE));
        // Pressure lasts until three times the reserve is free.
        assert!(pressure.observe(Some(space(899_999)), RESERVE));
        assert!(!pressure.observe(Some(space(900_000)), RESERVE));
    }

    #[test]
    fn a_failed_measurement_erases_nothing_and_keeps_the_state() {
        let pressure = under_pressure_now();
        assert!(
            !pressure.observe(None, NO_RESERVE),
            "nothing is erased on no measurement"
        );
        assert!(
            pressure.observe(Some(space(149_999)), NO_RESERVE),
            "the spell continues once a measurement says so"
        );
    }

    #[test]
    fn passes_under_pressure_are_spaced_and_cycles_always_run_one() {
        const SPACING: Duration = Duration::from_mins(10);
        const SOON: Duration = Duration::from_secs(1);
        let pressure = DiskPressure::default();
        let start = Instant::now();

        assert!(pressure.pass_due_at(false, true, SPACING, start));
        pressure.finish_pass_at(start + SOON);
        assert!(
            !pressure.pass_due_at(false, true, SPACING, start + SOON),
            "a round straight after a pass finished waits"
        );
        assert!(
            pressure.pass_due_at(true, false, SPACING, start + SOON),
            "a completed cycle always runs one"
        );
        assert!(
            !pressure.pass_due_at(false, true, SPACING, start + SPACING),
            "spaced from when the last pass finished, not when it started"
        );
        assert!(pressure.pass_due_at(false, true, SPACING, start + SOON + SPACING));
        assert!(
            !pressure.pass_due_at(false, false, SPACING, start + SPACING * 3),
            "nothing runs without pressure between cycles"
        );
    }

    #[test]
    fn records_go_farthest_first_and_demoted_ones_last() {
        let pressure = under_pressure_now();
        let (near, middle, far) = (key(0x01), key(0x40), key(0xF0));
        pressure.demote(RecordKind::Chunk, far);

        let order = pressure.erasure_order(
            RecordKind::Chunk,
            &self_id(),
            vec![near, far, middle],
            NO_LIMIT,
            |k| *k,
        );
        assert_eq!(order, vec![middle, near, far]);

        // A pointer at the same address is not demoted by the chunk's failure.
        let order = pressure.erasure_order(
            RecordKind::Pointer,
            &self_id(),
            vec![near, far],
            NO_LIMIT,
            |k| *k,
        );
        assert_eq!(order, vec![far, near]);
    }

    #[test]
    fn a_limit_takes_the_first_records_of_the_whole_order() {
        let pressure = under_pressure_now();
        let candidates: Vec<XorName> = (1..=9).map(|first| key(first * 0x10)).collect();
        pressure.demote(RecordKind::Chunk, key(0x90));
        let order = pressure.erasure_order(RecordKind::Chunk, &self_id(), candidates, 3, |k| *k);
        assert_eq!(order, vec![key(0x80), key(0x70), key(0x60)]);
    }

    #[test]
    fn no_candidate_waits_more_than_a_round_for_its_next_turn() {
        // Nothing is ever proven, so every candidate stays one for the whole
        // spell. Passes must keep reaching all of them, not settle on
        // retrying the farthest batch once each has failed once.
        const CANDIDATES: u8 = 5;
        const BATCH: usize = 2;
        const PASSES: usize = 12;
        let pressure = under_pressure_now();
        let candidates: Vec<XorName> = (1..=CANDIDATES).map(|first| key(first * 0x10)).collect();
        let passes_per_round = usize::from(CANDIDATES).div_ceil(BATCH);

        let mut turns: HashMap<XorName, Vec<usize>> = HashMap::new();
        for pass in 0..PASSES {
            let batch = pressure.erasure_order(
                RecordKind::Pointer,
                &self_id(),
                candidates.clone(),
                BATCH,
                |k| *k,
            );
            for key in batch {
                turns.entry(key).or_default().push(pass);
                pressure.demote(RecordKind::Pointer, key);
            }
        }

        assert_eq!(
            turns.len(),
            usize::from(CANDIDATES),
            "every candidate had a turn"
        );
        for (key, passes) in &turns {
            assert!(
                passes[0] < passes_per_round,
                "{key:?} first tried in the first round"
            );
            let longest_wait = passes
                .windows(2)
                .map(|pair| pair[1] - pair[0])
                .chain(std::iter::once(PASSES - passes[passes.len() - 1]))
                .max()
                .unwrap_or(PASSES);
            assert!(
                longest_wait <= passes_per_round,
                "{key:?} waited {longest_wait} passes for a turn"
            );
        }
    }

    #[test]
    fn new_candidates_arriving_do_not_stop_failed_ones_being_retried() {
        // A new candidate arrives every pass and nothing is ever proven. A
        // new one is always untried, so waiting for every candidate to have
        // failed would leave the farthest failed ones holding all other slots.
        const INITIAL: u8 = 8;
        const BATCH: usize = 3;
        const PASSES: u8 = 40;
        const MIN_TURNS: usize = 2;
        let pressure = under_pressure_now();
        let initial: Vec<XorName> = (1..=INITIAL).map(|first| key(first * 0x10)).collect();
        let mut candidates = initial.clone();

        let mut turns: HashMap<XorName, usize> = HashMap::new();
        for pass in 0..PASSES {
            let mut arrival = key(0x01);
            arrival[1] = pass;
            candidates.push(arrival);
            let batch = pressure.erasure_order(
                RecordKind::Chunk,
                &self_id(),
                candidates.clone(),
                BATCH,
                |k| *k,
            );
            for key in batch {
                *turns.entry(key).or_default() += 1;
                pressure.demote(RecordKind::Chunk, key);
            }
        }

        for key in &initial {
            let taken = turns.get(key).copied().unwrap_or_default();
            assert!(
                taken >= MIN_TURNS,
                "{key:?} had {taken} turns in {PASSES} passes"
            );
        }
    }

    #[test]
    fn demotions_end_with_the_spell_and_need_one_to_start() {
        let pressure = DiskPressure::default();
        let (near, far) = (key(0x01), key(0xF0));

        pressure.demote(RecordKind::Chunk, far);
        assert!(pressure.observe(Some(space(0)), NO_RESERVE));
        let order = pressure.erasure_order(
            RecordKind::Chunk,
            &self_id(),
            vec![near, far],
            NO_LIMIT,
            |k| *k,
        );
        assert_eq!(
            order,
            vec![far, near],
            "a demotion outside a spell is ignored"
        );

        pressure.demote(RecordKind::Chunk, far);
        assert!(!pressure.observe(Some(space(TOTAL)), NO_RESERVE));
        assert!(pressure.observe(Some(space(0)), NO_RESERVE));
        let order = pressure.erasure_order(
            RecordKind::Chunk,
            &self_id(),
            vec![near, far],
            NO_LIMIT,
            |k| *k,
        );
        assert_eq!(
            order,
            vec![far, near],
            "a new spell starts with no demotions"
        );
    }
}
