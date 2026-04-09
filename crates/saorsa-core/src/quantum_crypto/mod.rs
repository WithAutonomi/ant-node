// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Quantum-resistant cryptography module
//!
//! This module provides post-quantum cryptographic primitives including:
//! - ML-DSA (Module-Lattice Digital Signature Algorithm) for signatures

pub mod saorsa_transport_integration;

// Re-export saorsa-transport PQC functions for convenience
pub use self::saorsa_transport_integration::{generate_ml_dsa_keypair, ml_dsa_sign, ml_dsa_verify};

// Primary post-quantum cryptography types from saorsa-pqc 0.3.0
pub use saorsa_pqc::MlDsa65;
