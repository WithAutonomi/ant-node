//! Payment verification system for ant-node.
//!
//! This module implements the payment verification strategy:
//! 1. Check LRU cache for already-verified data
//! 2. Require and verify EVM/Arbitrum payment for new data
//!
//! # Default Policy
//!
//! **Production nodes require payment by default.**
//!
//! - EVM verification is always on — there is no way to disable it
//! - For unit tests, pre-populate the cache via `PaymentVerifier::cache_insert()`
//!
//! # Architecture
//!
//! ```text
//! PUT request received
//!        │
//!        ▼
//! ┌─────────────────────┐
//! │ Check LRU cache     │
//! └─────────┬───────────┘
//!           │
//!    ┌──────┴──────┐
//!    │             │
//!   HIT          MISS
//!    │             │
//!    ▼             ▼
//! Store (paid)   Require EVM payment
//! ```
//!
//! # Payment Flow
//!
//! All new data requires EVM payment:
//! 1. Client requests a quote from the node
//! 2. Node generates `PaymentQuote` with ML-DSA-65 signature
//! 3. Client pays on Arbitrum via `PaymentVault.payForQuotes()`
//! 4. Client sends PUT with `ProofOfPayment`
//! 5. Node verifies on-chain payment and stores data

mod cache;
pub mod metrics;
pub mod pricing;
pub mod proof;
pub mod quote;
pub mod single_node;
mod verifier;
pub mod wallet;

pub use cache::{CacheStats, VerifiedCache};
pub use metrics::QuotingMetricsTracker;
pub use pricing::calculate_price;
pub use proof::{
    deserialize_merkle_proof, deserialize_proof, detect_proof_type, serialize_merkle_proof,
    serialize_single_node_proof, PaymentProof, ProofType,
};
pub use quote::{wire_ml_dsa_signer, QuoteGenerator, XorName};
// Wire-side signature verification lives in ant-protocol. Re-exported here
// so `ant_node::payment::verify_*` keeps working for downstream callers.
pub use ant_protocol::payment::verify::{
    verify_merkle_candidate_signature, verify_quote_content, verify_quote_signature,
};
pub use single_node::SingleNodePayment;
pub use verifier::{
    EvmVerifierConfig, PaymentStatus, PaymentVerifier, PaymentVerifierConfig,
    MAX_PAYMENT_PROOF_SIZE_BYTES, MIN_PAYMENT_PROOF_SIZE_BYTES,
};
pub use wallet::{is_valid_address, parse_rewards_address, WalletConfig};
