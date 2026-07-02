//! Auditor-side per-target admission for outbound `AuditChallenge`s.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use saorsa_core::identity::PeerId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Maximum concurrent `AuditChallenge` requests this auditor may have in
/// flight to one target peer.
///
/// This intentionally matches the per-source digest admission cap enforced by
/// the already-deployed fleet. Waiting here happens before the response
/// deadline starts, so excess local bursts are serialized instead of being
/// converted into guaranteed remote admission drops and false timeouts.
pub(crate) const MAX_CONCURRENT_AUDIT_CHALLENGES_PER_TARGET: usize = 2;

#[derive(Debug)]
struct TargetLimiter {
    semaphore: Arc<Semaphore>,
    references: usize,
}

/// Shared limiter for all auditor-side flows that send `AuditChallenge`.
#[derive(Debug, Default)]
pub struct AuditChallengeCoordinator {
    targets: Mutex<HashMap<PeerId, TargetLimiter>>,
}

/// Permit held while one outbound challenge is in flight.
#[derive(Debug)]
pub(crate) struct AuditChallengePermit {
    coordinator: Arc<AuditChallengeCoordinator>,
    peer: PeerId,
    permit: Option<OwnedSemaphorePermit>,
}

impl AuditChallengeCoordinator {
    /// Create an empty coordinator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wait for a target-peer slot. Returns `None` only if the internal
    /// semaphore was closed, which the coordinator never does in production.
    pub(crate) async fn acquire(self: &Arc<Self>, peer: PeerId) -> Option<AuditChallengePermit> {
        let semaphore = {
            let mut targets = self.lock_targets();
            let entry = targets.entry(peer).or_insert_with(|| TargetLimiter {
                semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_CHALLENGES_PER_TARGET)),
                references: 0,
            });
            entry.references = entry.references.saturating_add(1);
            Arc::clone(&entry.semaphore)
        };

        semaphore.acquire_owned().await.map_or_else(
            |_| {
                self.release_reference(peer);
                None
            },
            |permit| {
                Some(AuditChallengePermit {
                    coordinator: Arc::clone(self),
                    peer,
                    permit: Some(permit),
                })
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn tracked_target_count(&self) -> usize {
        self.lock_targets().len()
    }

    fn release_reference(&self, peer: PeerId) {
        let mut targets = self.lock_targets();
        let Some(entry) = targets.get_mut(&peer) else {
            return;
        };
        entry.references = entry.references.saturating_sub(1);
        if entry.references == 0 {
            targets.remove(&peer);
        }
    }

    fn lock_targets(&self) -> std::sync::MutexGuard<'_, HashMap<PeerId, TargetLimiter>> {
        match self.targets.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl Drop for AuditChallengePermit {
    fn drop(&mut self) {
        let _permit = self.permit.take();
        self.coordinator.release_reference(self.peer);
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    const PEER_A: [u8; 32] = [0xA1; 32];
    const PEER_B: [u8; 32] = [0xB2; 32];
    const SHORT_WAIT: Duration = Duration::from_millis(50);

    fn peer(bytes: [u8; 32]) -> PeerId {
        PeerId::from_bytes(bytes)
    }

    #[tokio::test]
    async fn excess_challenges_wait_and_are_not_dropped() {
        let coordinator = Arc::new(AuditChallengeCoordinator::new());
        let target = peer(PEER_A);
        let first = coordinator.acquire(target).await;
        let second = coordinator.acquire(target).await;
        assert!(first.is_some());
        assert!(second.is_some());

        let acquired = Arc::new(AtomicUsize::new(0));
        let acquired_clone = Arc::clone(&acquired);
        let coordinator_clone = Arc::clone(&coordinator);
        let waiting = tokio::spawn(async move {
            let permit = coordinator_clone.acquire(target).await;
            if permit.is_some() {
                acquired_clone.fetch_add(1, Ordering::SeqCst);
            }
            permit
        });

        tokio::time::sleep(SHORT_WAIT).await;
        assert_eq!(acquired.load(Ordering::SeqCst), 0);

        drop(first);
        let third = tokio::time::timeout(SHORT_WAIT, waiting).await;
        assert!(third.is_ok());
        assert_eq!(acquired.load(Ordering::SeqCst), 1);

        drop(second);
        if let Ok(joined) = third {
            match joined {
                Ok(permit) => drop(permit),
                Err(e) => panic!("waiting task failed: {e}"),
            }
        }
        assert_eq!(coordinator.tracked_target_count(), 0);
    }

    #[tokio::test]
    async fn cross_peer_parallelism_is_preserved() {
        let coordinator = Arc::new(AuditChallengeCoordinator::new());
        let target_a = peer(PEER_A);
        let target_b = peer(PEER_B);
        let first_a = coordinator.acquire(target_a).await;
        let second_a = coordinator.acquire(target_a).await;
        assert!(first_a.is_some());
        assert!(second_a.is_some());

        let coordinator_clone = Arc::clone(&coordinator);
        let acquired_b = tokio::spawn(async move { coordinator_clone.acquire(target_b).await });
        let result = tokio::time::timeout(SHORT_WAIT, acquired_b).await;
        assert!(result.is_ok());
    }
}
