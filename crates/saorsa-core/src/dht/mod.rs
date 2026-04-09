//! Distributed Hash Table implementations
//!
//! This module provides the DHT as a **peer phonebook**: routing table,
//! peer discovery, liveness, and trust-weighted selection. Data storage
//! and replication are handled by the application layer (saorsa-node).

pub mod core_engine;
pub mod network_integration;

// Re-export core engine types
pub use core_engine::{AddressType, AdmissionResult, DhtCoreEngine, DhtKey, RoutingTableEvent};

/// DHT key type (256-bit)
pub type Key = [u8; 32];

#[cfg(test)]
mod security_tests;
