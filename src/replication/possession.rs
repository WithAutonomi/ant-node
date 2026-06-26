//! Delayed possession verification for fresh replication (ADR-0003).
//!
//! After a node fresh-replicates a chunk, every close-group peer responsible
//! for it is checked 5-15 minutes later for actual possession. A peer that
//! holds the chunk earns nothing — storing what it was paid to store is the
//! baseline expectation, not meritorious; a peer confirmed *not* to hold it is
//! penalised at `AuditChallenge` severity. Delivery of the original push is
//! irrelevant: a peer the push never reached is still checked and penalised if
//! it lacks the chunk. A peer merely unreachable at check time yields no
//! verdict — it is re-attempted under a bounded grace and never penalised as
//! absent.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use tokio_util::sync::CancellationToken;

use crate::ant_protocol::XorName;
use crate::logging::{debug, warn};
use crate::replication::config::{
    self, POSSESSION_CHECK_MAX_ATTEMPTS, POSSESSION_CHECK_RETRY_BACKOFF, POSSESSION_CHECK_TIMEOUT,
    REPLICATION_PROTOCOL_ID,
};
use crate::replication::protocol::{
    ReplicationMessage, ReplicationMessageBody, VerificationRequest,
};

/// A scheduled possession check for one freshly-replicated chunk.
pub struct PossessionCheckEvent {
    /// Content-address of the chunk.
    pub key: XorName,
    /// Close-group peers responsible for holding it (excludes self).
    pub peers: Vec<PeerId>,
}

/// Verdict of probing a single peer for possession of a chunk.
enum ProbeOutcome {
    /// Peer confirmed it holds the chunk.
    Present,
    /// Peer confirmed it does not hold the chunk.
    Absent,
    /// No verdict obtained (timeout / transport error / malformed response).
    NoVerdict,
}

/// Pick a randomised delay in `[min, max]` to wait before a possession check
/// runs. The bounds come from `ReplicationConfig` (defaulting to
/// `POSSESSION_CHECK_DELAY_MIN`/`MAX`) so tests can shorten them.
#[must_use]
pub fn random_delay(min: Duration, max: Duration) -> Duration {
    let to_millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let min_ms = to_millis(min);
    let max_ms = to_millis(max);
    if min_ms >= max_ms {
        return min;
    }
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

/// Run the possession check for one chunk against every responsible peer.
///
/// Penalises each peer confirmed absent at `AuditChallenge` severity, leaves
/// present peers unrewarded, and never penalises a peer that only failed to
/// yield a verdict.
pub async fn run_possession_check(
    key: XorName,
    peers: Vec<PeerId>,
    p2p_node: &Arc<P2PNode>,
    shutdown: &CancellationToken,
) {
    let key_hex = hex::encode(key);
    for peer in peers {
        if shutdown.is_cancelled() {
            return;
        }
        match probe_with_grace(&key, &peer, p2p_node, shutdown).await {
            ProbeOutcome::Present => {
                debug!("Possession check: {peer} holds {key_hex}");
            }
            ProbeOutcome::Absent => {
                warn!(
                    "Possession check: {peer} is missing {key_hex}; penalising at audit severity"
                );
                p2p_node
                    .report_trust_event(
                        &peer,
                        TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
                    )
                    .await;
            }
            ProbeOutcome::NoVerdict => {
                debug!(
                    "Possession check: no verdict from {peer} for {key_hex} after grace; \
                     not penalised"
                );
            }
        }
    }
}

/// Probe a peer for possession, re-attempting on no-verdict up to the grace
/// bound. A definite Present/Absent verdict short-circuits immediately.
async fn probe_with_grace(
    key: &XorName,
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    shutdown: &CancellationToken,
) -> ProbeOutcome {
    for attempt in 1..=POSSESSION_CHECK_MAX_ATTEMPTS {
        match probe_once(key, peer, p2p_node).await {
            ProbeOutcome::NoVerdict if attempt < POSSESSION_CHECK_MAX_ATTEMPTS => {
                tokio::select! {
                    () = shutdown.cancelled() => return ProbeOutcome::NoVerdict,
                    () = tokio::time::sleep(POSSESSION_CHECK_RETRY_BACKOFF) => {}
                }
            }
            outcome => return outcome,
        }
    }
    ProbeOutcome::NoVerdict
}

/// Send one presence-only `VerificationRequest` and interpret the response.
async fn probe_once(key: &XorName, peer: &PeerId, p2p_node: &Arc<P2PNode>) -> ProbeOutcome {
    let request = VerificationRequest {
        keys: vec![*key],
        // Presence-only: no paid-list status is needed to judge possession.
        paid_list_check_indices: Vec::new(),
    };
    let msg = ReplicationMessage {
        request_id: rand::random(),
        body: ReplicationMessageBody::VerificationRequest(request),
    };
    let Ok(encoded) = msg.encode() else {
        warn!(
            "Failed to encode possession request for {}",
            hex::encode(key)
        );
        return ProbeOutcome::NoVerdict;
    };

    let response = match p2p_node
        .send_request(
            peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            POSSESSION_CHECK_TIMEOUT,
        )
        .await
    {
        Ok(response) => response,
        Err(e) => {
            debug!("Possession probe to {peer} failed: {e}");
            return ProbeOutcome::NoVerdict;
        }
    };

    let decoded = match ReplicationMessage::decode(&response.data) {
        Ok(decoded) => decoded,
        Err(e) => {
            debug!("Failed to decode possession response from {peer}: {e}");
            return ProbeOutcome::NoVerdict;
        }
    };

    let ReplicationMessageBody::VerificationResponse(resp) = decoded.body else {
        debug!("Unexpected possession response type from {peer}");
        return ProbeOutcome::NoVerdict;
    };

    match resp.results.iter().find(|r| r.key == *key) {
        Some(result) if result.present => ProbeOutcome::Present,
        Some(_) => ProbeOutcome::Absent,
        None => ProbeOutcome::NoVerdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::config::{POSSESSION_CHECK_DELAY_MAX, POSSESSION_CHECK_DELAY_MIN};

    #[test]
    fn random_delay_is_within_bounds() {
        for _ in 0..100 {
            let d = random_delay(POSSESSION_CHECK_DELAY_MIN, POSSESSION_CHECK_DELAY_MAX);
            assert!(d >= POSSESSION_CHECK_DELAY_MIN);
            assert!(d <= POSSESSION_CHECK_DELAY_MAX);
        }
    }
}
