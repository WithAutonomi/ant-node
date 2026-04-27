//! `SingleNode` payment re-exports from [`ant_protocol`].
//!
//! Extracted to the [`ant_protocol`] crate in 0.11 so `pay` and
//! `verify` stay co-located in a single crate that both the client and
//! node test against end to end. Internal callers using
//! `crate::payment::single_node::…` keep working unchanged.

pub use ant_protocol::payment::single_node::{QuotePaymentInfo, SingleNodePayment};
