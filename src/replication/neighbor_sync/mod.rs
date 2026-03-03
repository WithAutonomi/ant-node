//! Neighbor sync subsystem (Section 6.2).
//!
//! Implements the round-robin neighbor sync repair protocol:
//! - [`scheduler`] - Round-robin cycle management (snapshot, cursor, cooldown)
//! - [`hints`] - Hint construction (sender-side) and admission (receiver-side)
//! - [`session`] - Sync session logic (bidirectional / outbound-only)

pub mod hints;
pub mod scheduler;
pub mod session;

pub use hints::{AdmissionResult, HintsForPeer};
pub use scheduler::SyncScheduler;
pub use session::{AdmittedKey, SessionDirection, SessionResult};
