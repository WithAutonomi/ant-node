//! Replication subsystem for Kademlia-style data replication.
//!
//! Implements the full specification from `docs/REPLICATION_DESIGN.md`:
//! - Fresh replication (PoP-validated push)
//! - Neighbor sync repair (round-robin hint exchange)
//! - Quorum verification with dual-evidence (presence + paid-list)
//! - `PaidForList` authorization and persistence
//! - Storage audits (challenge-response anti-outsourcing)
//! - Bootstrap sync logic
//! - `EigenTrust` integration for trust evidence
//!
//! # Module Structure
//!
//! - [`params`] - Tunable parameters and `ReplicationConfig`
//! - [`types`] - Core types (evidence, pipeline, bootstrap claim tracking)
//! - [`routing`] - Routing helpers (close group, responsibility, quorum thresholds)
//! - [`protocol`] - Wire protocol message types
//! - [`paid_list`] - Persistent `PaidForList`
//! - [`fresh`] - Fresh replication (PoP-validated push)
//! - [`state_machine`] - Receiver verification state machine
//! - [`verification`] - Quorum verification logic (dual-evidence)
//! - [`fetch`] - Fetch queue and worker logic
//! - [`neighbor_sync`] - Neighbor sync repair (scheduler, hints, session)
//! - [`prune`] - Prune tracking with time-based hysteresis
//! - [`persistence`] - Atomic disk I/O helpers

pub mod audit;
pub mod bootstrap;
pub mod eigentrust;
pub mod fetch;
pub mod fresh;
pub mod neighbor_sync;
pub mod paid_list;
pub mod params;
pub mod persistence;
pub mod protocol;
pub mod prune;
pub mod routing;
pub mod self_lookup;
pub mod state_machine;
pub mod types;
pub mod verification;

pub use fetch::{FetchAttemptResult, FetchEntry, FetchQueue};
pub use paid_list::PaidForList;
pub use params::ReplicationConfig;
pub use protocol::{ReplicationMessage, REPLICATION_PROTOCOL_ID};
pub use prune::{PrunePassResult, PruneTracker};
pub use state_machine::VerificationState;
pub use types::{
    BootstrapClaimTracker, HintPipeline, PaidListEvidence, PeerKeyEvidence, PresenceEvidence,
    VerificationContext,
};
pub use verification::{KeyEvidenceTally, KeyVerifyPlan, VerifyOutcome};
