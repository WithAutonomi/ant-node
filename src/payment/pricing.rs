//! Quadratic pricing with a baseline floor.
//!
//! ADR-0004: the pricing formula is now the **single source of truth** in
//! `ant-protocol` (`ant_protocol::payment::pricing`), so the node (when pricing
//! a quote) and the client (when verifying the forced price before paying)
//! compute byte-for-byte identical prices and can never drift. This module
//! re-exports it so every existing `crate::payment::pricing::…` caller keeps
//! working unchanged.
//!
//! See `ant-protocol/src/payment/pricing.rs` for the formula, constants, and
//! the full unit-test suite.

pub use ant_protocol::payment::pricing::{calculate_price, derive_records_stored_from_price};
