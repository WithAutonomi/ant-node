// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Node-wide hole-punch coordinator back-pressure (Tier 4 lite).
//!
//! Every connection that lands at a node and acts as a hole-punch coordinator
//! shares one [`RelaySlotTable`](crate::relay_slot_table::RelaySlotTable). The table caps the number of in-flight
//! `(initiator, target)` relay sessions across the entire node, so a storm
//! of cold-starting peers cannot pile up unbounded coordination work on a
//! single bootstrap. When the cap is reached, additional `PUNCH_ME_NOW`
//! relay frames are silently refused — the initiator's per-attempt timeout
//! drives it to its next preferred coordinator (Tier 2 rotation).
//!
//! ## Lifetime model
//!
//! A "slot" represents an active coordination *session*: the same
//! `(initiator_addr, target_peer_id)` pair sending one or more
//! `PUNCH_ME_NOW` frames over the lifetime of a hole-punch attempt. The
//! coordinator cannot directly observe whether a punch ultimately succeeded
//! (the punch traffic flows initiator↔target, bypassing the coordinator),
//! so slot release happens via three mechanisms:
//!
//! 1. **Inactivity timeout** ([`RelaySlotTable::idle_timeout`](crate::relay_slot_table::RelaySlotTable::idle_timeout)). If no new
//!    rounds for the same key arrive within this window the session is
//!    considered done — either the punch succeeded (no more rounds needed)
//!    or it definitively failed (the initiator rotated away). Default 5s.
//!
//! 2. **Connection close** via `RelaySlotTable::release_for_initiator`.
//!    When the initiator's connection drops, every slot it owned is
//!    reclaimed immediately rather than waiting for the inactivity timeout.
//!    Called from `BootstrapCoordinator::Drop`.
//!
//! 3. **Explicit re-arm refresh**. A re-sent frame for the same key
//!    refreshes the timestamp without consuming additional capacity.
//!
//! ## Key choice
//!
//! Slots are keyed by `(initiator_addr, target_peer_id)` rather than
//! `(initiator_peer_id, target_peer_id)` because the cryptographic PeerId
//! is not available inside the QUIC connection state machine where the
//! `PUNCH_ME_NOW` frame is processed (PQC auth state lives one layer up
//! in `P2pEndpoint`). The remote socket address is constant across rounds
//! within a session and unique enough across distinct initiators to give
//! correct dedup behaviour for the back-pressure cap.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

/// Cryptographic peer identifier — BLAKE3 hash of an ML-DSA-65 public key.
/// Local alias to keep the table independent of the connection layer.
pub(crate) type RelayTargetId = [u8; 32];

/// Minimum interval between consecutive amortized sweeps. Sweeping less
/// often than this on a hot path keeps the per-frame overhead bounded
/// without letting expired entries pile up.
const SWEEP_AMORTIZATION_INTERVAL: Duration = Duration::from_millis(100);

/// One refusal warning every this many refusals, so an operator gets a
/// log line at the start of a storm and periodically thereafter without
/// flooding logs at line-rate.
const REFUSAL_WARN_INTERVAL: u64 = 16;

/// Node-wide table of in-flight hole-punch coordinator relay slots.
///
/// Cheap to clone via `Arc`. Internal state is guarded by a single
/// `Mutex`; contention is bounded because each acquire/release holds the
/// lock for a short critical section (a HashMap lookup plus optional
/// amortized retain).
pub struct RelaySlotTable {
    inner: Mutex<RelaySlotTableInner>,
    capacity: usize,
    idle_timeout: Duration,
    backpressure_refusals: AtomicU64,
}

struct RelaySlotTableInner {
    slots: HashMap<(SocketAddr, RelayTargetId), Instant>,
    last_swept: Instant,
}

impl RelaySlotTable {
    /// Create a new shared table with the given capacity and idle timeout.
    ///
    /// `capacity` caps the number of distinct simultaneous in-flight
    /// `(initiator_addr, target_peer_id)` sessions across the node.
    /// `idle_timeout` is how long a slot lingers after its last refresh
    /// before being reclaimed by the inline sweep — picks up the slack
    /// when an initiator stops sending without explicitly releasing
    /// (e.g. NAT rebind or process crash).
    pub fn new(capacity: usize, idle_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(RelaySlotTableInner {
                slots: HashMap::new(),
                last_swept: Instant::now(),
            }),
            capacity,
            idle_timeout,
            backpressure_refusals: AtomicU64::new(0),
        }
    }

    /// Try to acquire a slot for `(initiator_addr, target_peer_id)`.
    ///
    /// Returns `true` if the relay should proceed, `false` if the table
    /// is at capacity. A re-acquisition for an already-held key always
    /// succeeds and refreshes the timestamp without consuming additional
    /// capacity — exactly what multi-round coordination needs.
    pub(crate) fn try_acquire(
        &self,
        initiator_addr: SocketAddr,
        target_peer_id: RelayTargetId,
        now: Instant,
    ) -> bool {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::sweep_if_due(&mut inner, self.idle_timeout, now);

        let key = (initiator_addr, target_peer_id);
        let already_active = inner.slots.contains_key(&key);
        if !already_active && inner.slots.len() >= self.capacity {
            // Drop the lock before logging so the warn! call cannot
            // back-pressure the lock holder under contention.
            let active = inner.slots.len();
            drop(inner);
            let prior = self.backpressure_refusals.fetch_add(1, Ordering::Relaxed);
            // Log once at first refusal, then periodically.
            if prior == 0 || (prior + 1).is_multiple_of(REFUSAL_WARN_INTERVAL) {
                warn!(
                    "hole-punch coordinator at capacity: refused relay #{} ({}/{} slots in use, initiator={})",
                    prior + 1,
                    active,
                    self.capacity,
                    initiator_addr,
                );
            } else {
                debug!(
                    "hole-punch relay refused (back-pressure): initiator={} target={}",
                    initiator_addr,
                    hex::encode(&target_peer_id[..8])
                );
            }
            return false;
        }
        inner.slots.insert(key, now);
        true
    }

    /// Explicitly release every slot owned by `initiator_addr`. Called
    /// from `BootstrapCoordinator::Drop` when the initiator's connection
    /// closes, so the table doesn't have to wait out the idle timeout to
    /// reclaim capacity for a known-dead session.
    pub(crate) fn release_for_initiator(&self, initiator_addr: SocketAddr) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.slots.retain(|(addr, _), _| *addr != initiator_addr);
    }

    /// Total number of relay frames refused since the table was created.
    pub fn backpressure_refusals(&self) -> u64 {
        self.backpressure_refusals.load(Ordering::Relaxed)
    }

    /// Configured capacity (maximum simultaneous active slots).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Configured idle-release timeout for inactive slots.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Snapshot of the current active slot count. Test/diagnostic only;
    /// callers must treat the value as advisory because the table may
    /// change between calls.
    pub fn active_count(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.slots.len(),
            Err(poisoned) => poisoned.into_inner().slots.len(),
        }
    }

    /// Amortized sweep: prune slots whose last refresh is older than the
    /// idle timeout, but only if the previous sweep was at least
    /// [`SWEEP_AMORTIZATION_INTERVAL`] ago. This bounds the per-frame
    /// retain cost on hot paths while still draining stale entries
    /// promptly enough to free capacity ahead of the next storm.
    fn sweep_if_due(inner: &mut RelaySlotTableInner, idle_timeout: Duration, now: Instant) {
        if now.duration_since(inner.last_swept) < SWEEP_AMORTIZATION_INTERVAL {
            return;
        }
        inner
            .slots
            .retain(|_, arrived_at| now.duration_since(*arrived_at) < idle_timeout);
        inner.last_swept = now;
    }
}

impl std::fmt::Debug for RelaySlotTable {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("RelaySlotTable")
            .field("capacity", &self.capacity)
            .field("idle_timeout", &self.idle_timeout)
            .field(
                "backpressure_refusals",
                &self.backpressure_refusals.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(byte: u8) -> RelayTargetId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn under_capacity_acquires() {
        let table = RelaySlotTable::new(4, Duration::from_secs(5));
        let now = Instant::now();
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        assert_eq!(table.active_count(), 1);
        assert_eq!(table.backpressure_refusals(), 0);
    }

    #[test]
    fn at_capacity_refuses_silently() {
        let table = RelaySlotTable::new(2, Duration::from_secs(5));
        let now = Instant::now();
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        assert!(table.try_acquire(addr(5001), target(0x02), now));
        assert!(!table.try_acquire(addr(5002), target(0x03), now));
        assert_eq!(table.active_count(), 2);
        assert_eq!(table.backpressure_refusals(), 1);
    }

    #[test]
    fn re_arm_refreshes_without_consuming_capacity() {
        let table = RelaySlotTable::new(2, Duration::from_secs(5));
        let now = Instant::now();
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        let later = now + Duration::from_millis(500);
        assert!(table.try_acquire(addr(5000), target(0x01), later));
        assert_eq!(
            table.active_count(),
            1,
            "re-arm must not allocate a second slot"
        );
    }

    #[test]
    fn idle_sweep_reclaims_stale_slots() {
        let timeout = Duration::from_secs(5);
        let table = RelaySlotTable::new(2, timeout);
        let now = Instant::now();
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        assert!(table.try_acquire(addr(5001), target(0x02), now));
        // Past idle timeout AND past sweep amortization interval.
        let much_later = now + timeout + Duration::from_secs(1);
        assert!(table.try_acquire(addr(5002), target(0x03), much_later));
        assert_eq!(
            table.active_count(),
            1,
            "stale slots reclaimed by inline sweep before the cap check"
        );
        assert_eq!(table.backpressure_refusals(), 0);
    }

    #[test]
    fn release_for_initiator_drops_owned_slots_only() {
        let table = RelaySlotTable::new(8, Duration::from_secs(5));
        let now = Instant::now();
        // Two distinct sessions for initiator A.
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        assert!(table.try_acquire(addr(5000), target(0x02), now));
        // One session for a different initiator B.
        assert!(table.try_acquire(addr(5999), target(0x03), now));
        assert_eq!(table.active_count(), 3);

        table.release_for_initiator(addr(5000));
        assert_eq!(
            table.active_count(),
            1,
            "release must drop slots for the named initiator only"
        );
        // The B slot is still there.
        let later = now + Duration::from_millis(50);
        assert!(table.try_acquire(addr(5999), target(0x03), later));
        assert_eq!(table.active_count(), 1);
    }

    #[test]
    fn refusal_count_accumulates_across_distinct_targets() {
        let table = RelaySlotTable::new(1, Duration::from_secs(5));
        let now = Instant::now();
        assert!(table.try_acquire(addr(5000), target(0x01), now));
        // Three distinct refusals at the same instant — sweep won't fire.
        assert!(!table.try_acquire(addr(5001), target(0x02), now));
        assert!(!table.try_acquire(addr(5002), target(0x03), now));
        assert!(!table.try_acquire(addr(5003), target(0x04), now));
        assert_eq!(table.backpressure_refusals(), 3);
    }
}
