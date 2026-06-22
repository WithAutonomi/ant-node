//! Runtime diagnostics for one-off production investigations.
//!
//! The diagnostics in this module are deliberately logging-only and runtime
//! gated so normal nodes keep their existing behaviour unless an operator opts
//! a canary process in via environment variables.

pub mod memory;
