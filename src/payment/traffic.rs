//! Cumulative EVM RPC call accounting (V2-834 Part D.3).
//!
//! Both on-chain reads go through `evmlib` → `alloy`, which builds a fresh
//! HTTP provider per call and serialises JSON-RPC inside its own transport,
//! so request/response body sizes are not observable from ant-node without a
//! transport-layer change in `evmlib`. This table therefore records calls and
//! outcomes only. EVM RPC is HTTPS over TCP and sits outside the UDP
//! reconciliation invariant; call counts are what is needed to bound it.

use std::sync::atomic::{AtomicU64, Ordering};

/// Which on-chain read was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmRpcCall {
    /// `IPaymentVault::completedPayments(quote_hash)` (single-node path).
    CompletedPayments,
    /// `getCompletedMerklePayment(pool_hash)` (merkle batch path).
    CompletedMerklePayment,
}

impl EvmRpcCall {
    const N: usize = 2;

    const fn index(self) -> usize {
        match self {
            Self::CompletedPayments => 0,
            Self::CompletedMerklePayment => 1,
        }
    }
}

static OK_COUNT: [AtomicU64; EvmRpcCall::N] = [const { AtomicU64::new(0) }; EvmRpcCall::N];
static ERR_COUNT: [AtomicU64; EvmRpcCall::N] = [const { AtomicU64::new(0) }; EvmRpcCall::N];

/// Record the outcome of one on-chain read.
pub fn record(call: EvmRpcCall, ok: bool) {
    let table = if ok { &OK_COUNT } else { &ERR_COUNT };
    table[call.index()].fetch_add(1, Ordering::Relaxed);
}

/// Emit the cumulative EVM RPC call figures as one INFO line, target
/// `ant_node::payment::traffic`.
pub fn log_evm_rpc_summary() {
    use EvmRpcCall as C;

    let ok = |c: C| OK_COUNT[c.index()].load(Ordering::Relaxed);
    let err = |c: C| ERR_COUNT[c.index()].load(Ordering::Relaxed);

    crate::logging::info!(
        target: "ant_node::payment::traffic",
        completed_payments_ok_count = ok(C::CompletedPayments),
        completed_payments_err_count = err(C::CompletedPayments),
        merkle_payment_ok_count = ok(C::CompletedMerklePayment),
        merkle_payment_err_count = err(C::CompletedMerklePayment),
        "evm rpc summary (cumulative)"
    );
}
