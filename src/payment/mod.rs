//! Payment verification system for saorsa-node.
//!
//! This module implements the payment verification strategy:
//! 1. Check LRU cache for already-verified data
//! 2. Require and verify EVM/Arbitrum payment for new data
//!
//! # Default Policy
//!
//! **Production nodes require payment by default.**
//!
//! - `PaymentVerifierConfig::default()` has `evm.enabled = true`
//! - `PaymentConfig::default()` has `enabled = true`
//! - Test environments can disable via CLI flag `--disable-payment-verification`
//! - Test utilities explicitly disable EVM verification for unit tests
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
pub use proof::{deserialize_proof, PaymentProof};
pub use quote::{verify_quote_content, wire_ml_dsa_signer, QuoteGenerator, XorName};
pub use single_node::SingleNodePayment;
pub use verifier::{EvmVerifierConfig, PaymentStatus, PaymentVerifier, PaymentVerifierConfig};
pub use wallet::{is_valid_address, parse_rewards_address, WalletConfig};
