//! Cumulative chunk-RPC traffic accounting (V2-834 Part D.1).
//!
//! Client and community chunk serving flowed through saorsa-core's generic
//! wire counters, indistinguishable from DHT messaging. This module keeps
//! process-global relaxed-atomic tables, in the same style as the replication
//! table in [`crate::replication::protocol`], so "serving user downloads" can
//! be separated from everything else in `wire_tx_bytes`.
//!
//! Requests are counted at decode (by request kind) and responses at
//! send-success (by kind × outcome), so the tx figures are bytes confirmed
//! handed to the transport, not bytes merely encoded.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::ant_protocol::{ChunkGetResponse, ChunkMessageBody, ChunkPutResponse};

/// Kind of an inbound chunk message, for the rx table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkRequestKind {
    Get,
    Put,
    Quote,
    MerkleQuote,
    QuoteV2,
    MerkleQuoteV2,
    /// A non-request variant (responses meant for client subscribers) or an
    /// unknown future variant.
    Other,
    /// Bytes that failed `ChunkMessage::decode`.
    DecodeError,
}

impl ChunkRequestKind {
    const N: usize = 8;

    const fn index(self) -> usize {
        match self {
            Self::Get => 0,
            Self::Put => 1,
            Self::Quote => 2,
            Self::MerkleQuote => 3,
            Self::QuoteV2 => 4,
            Self::MerkleQuoteV2 => 5,
            Self::Other => 6,
            Self::DecodeError => 7,
        }
    }
}

/// Kind × outcome of an outbound chunk response, for the tx table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkResponseKey {
    GetSuccess,
    GetNotFound,
    GetError,
    PutSuccess,
    PutAlreadyExists,
    PutPaymentRequired,
    PutError,
    Quote,
    MerkleQuote,
    QuoteV2,
    MerkleQuoteV2,
    /// A response variant this table does not itemise (e.g. an `Other`
    /// outcome on a `#[non_exhaustive]` enum).
    Other,
}

impl ChunkResponseKey {
    const N: usize = 12;

    const fn index(self) -> usize {
        match self {
            Self::GetSuccess => 0,
            Self::GetNotFound => 1,
            Self::GetError => 2,
            Self::PutSuccess => 3,
            Self::PutAlreadyExists => 4,
            Self::PutPaymentRequired => 5,
            Self::PutError => 6,
            Self::Quote => 7,
            Self::MerkleQuote => 8,
            Self::QuoteV2 => 9,
            Self::MerkleQuoteV2 => 10,
            Self::Other => 11,
        }
    }
}

impl ChunkRequestKind {
    /// Classify a decoded inbound message.
    pub fn of(body: &ChunkMessageBody) -> Self {
        match body {
            ChunkMessageBody::GetRequest(_) => Self::Get,
            ChunkMessageBody::PutRequest(_) => Self::Put,
            ChunkMessageBody::QuoteRequest(_) => Self::Quote,
            ChunkMessageBody::MerkleCandidateQuoteRequest(_) => Self::MerkleQuote,
            ChunkMessageBody::QuoteRequestV2(_) => Self::QuoteV2,
            ChunkMessageBody::MerkleCandidateQuoteRequestV2(_) => Self::MerkleQuoteV2,
            _ => Self::Other,
        }
    }
}

impl ChunkResponseKey {
    /// Classify a GET response by outcome.
    pub fn of_get(response: &ChunkGetResponse) -> Self {
        match response {
            ChunkGetResponse::Success { .. } => Self::GetSuccess,
            ChunkGetResponse::NotFound { .. } => Self::GetNotFound,
            ChunkGetResponse::Error(_) => Self::GetError,
            _ => Self::Other,
        }
    }

    /// Classify a PUT response by outcome.
    pub fn of_put(response: &ChunkPutResponse) -> Self {
        match response {
            ChunkPutResponse::Success { .. } => Self::PutSuccess,
            ChunkPutResponse::AlreadyExists { .. } => Self::PutAlreadyExists,
            ChunkPutResponse::PaymentRequired { .. } => Self::PutPaymentRequired,
            ChunkPutResponse::Error(_) => Self::PutError,
            _ => Self::Other,
        }
    }
}

static RX_BYTES: [AtomicU64; ChunkRequestKind::N] =
    [const { AtomicU64::new(0) }; ChunkRequestKind::N];
static RX_COUNT: [AtomicU64; ChunkRequestKind::N] =
    [const { AtomicU64::new(0) }; ChunkRequestKind::N];
static TX_BYTES: [AtomicU64; ChunkResponseKey::N] =
    [const { AtomicU64::new(0) }; ChunkResponseKey::N];
static TX_COUNT: [AtomicU64; ChunkResponseKey::N] =
    [const { AtomicU64::new(0) }; ChunkResponseKey::N];
/// Encoded responses whose transport send failed (not in `TX_*`).
static SEND_FAILED_BYTES: AtomicU64 = AtomicU64::new(0);
static SEND_FAILED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Record one inbound chunk message at decode time (wire length).
pub fn record_rx(kind: ChunkRequestKind, bytes: usize) {
    let i = kind.index();
    RX_BYTES[i].fetch_add(bytes as u64, Ordering::Relaxed);
    RX_COUNT[i].fetch_add(1, Ordering::Relaxed);
}

/// Record one chunk response confirmed handed to the transport.
pub fn record_tx(key: ChunkResponseKey, bytes: usize) {
    let i = key.index();
    TX_BYTES[i].fetch_add(bytes as u64, Ordering::Relaxed);
    TX_COUNT[i].fetch_add(1, Ordering::Relaxed);
}

/// Record one encoded chunk response whose send failed.
pub fn record_send_failed(bytes: usize) {
    SEND_FAILED_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    SEND_FAILED_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Emit the cumulative chunk-RPC traffic as INFO summary lines, target
/// `ant_node::storage::traffic`.
///
/// Flat snake-case keys like the replication summary. Two lines sharing the
/// same target and message, distinguished by `group`: rx by request kind
/// (`group = 1`) and tx by kind × outcome (`group = 2`), keeping each under
/// `tracing`'s 32-field cap.
pub fn log_chunk_rpc_traffic_summary() {
    use ChunkRequestKind as Q;
    use ChunkResponseKey as R;

    let rb = |k: Q| RX_BYTES[k.index()].load(Ordering::Relaxed);
    let rc = |k: Q| RX_COUNT[k.index()].load(Ordering::Relaxed);
    let tb = |k: R| TX_BYTES[k.index()].load(Ordering::Relaxed);
    let tc = |k: R| TX_COUNT[k.index()].load(Ordering::Relaxed);

    crate::logging::info!(
        target: "ant_node::storage::traffic",
        group = 1,
        get_rx_bytes = rb(Q::Get), get_rx_count = rc(Q::Get),
        put_rx_bytes = rb(Q::Put), put_rx_count = rc(Q::Put),
        quote_rx_bytes = rb(Q::Quote), quote_rx_count = rc(Q::Quote),
        merkle_quote_rx_bytes = rb(Q::MerkleQuote), merkle_quote_rx_count = rc(Q::MerkleQuote),
        quote_v2_rx_bytes = rb(Q::QuoteV2), quote_v2_rx_count = rc(Q::QuoteV2),
        merkle_quote_v2_rx_bytes = rb(Q::MerkleQuoteV2),
        merkle_quote_v2_rx_count = rc(Q::MerkleQuoteV2),
        other_rx_bytes = rb(Q::Other), other_rx_count = rc(Q::Other),
        decode_error_rx_bytes = rb(Q::DecodeError), decode_error_rx_count = rc(Q::DecodeError),
        "chunk rpc traffic summary (cumulative)"
    );

    crate::logging::info!(
        target: "ant_node::storage::traffic",
        group = 2,
        get_success_tx_bytes = tb(R::GetSuccess), get_success_tx_count = tc(R::GetSuccess),
        get_not_found_tx_bytes = tb(R::GetNotFound), get_not_found_tx_count = tc(R::GetNotFound),
        get_error_tx_bytes = tb(R::GetError), get_error_tx_count = tc(R::GetError),
        put_success_tx_bytes = tb(R::PutSuccess), put_success_tx_count = tc(R::PutSuccess),
        put_already_exists_tx_bytes = tb(R::PutAlreadyExists),
        put_already_exists_tx_count = tc(R::PutAlreadyExists),
        put_payment_required_tx_bytes = tb(R::PutPaymentRequired),
        put_payment_required_tx_count = tc(R::PutPaymentRequired),
        put_error_tx_bytes = tb(R::PutError), put_error_tx_count = tc(R::PutError),
        quote_tx_bytes = tb(R::Quote), quote_tx_count = tc(R::Quote),
        merkle_quote_tx_bytes = tb(R::MerkleQuote), merkle_quote_tx_count = tc(R::MerkleQuote),
        quote_v2_tx_bytes = tb(R::QuoteV2), quote_v2_tx_count = tc(R::QuoteV2),
        merkle_quote_v2_tx_bytes = tb(R::MerkleQuoteV2),
        merkle_quote_v2_tx_count = tc(R::MerkleQuoteV2),
        other_tx_bytes = tb(R::Other), other_tx_count = tc(R::Other),
        send_failed_tx_bytes = SEND_FAILED_BYTES.load(Ordering::Relaxed),
        send_failed_tx_count = SEND_FAILED_COUNT.load(Ordering::Relaxed),
        "chunk rpc traffic summary (cumulative)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_are_distinct_and_in_range() {
        let req = [
            ChunkRequestKind::Get,
            ChunkRequestKind::Put,
            ChunkRequestKind::Quote,
            ChunkRequestKind::MerkleQuote,
            ChunkRequestKind::QuoteV2,
            ChunkRequestKind::MerkleQuoteV2,
            ChunkRequestKind::Other,
            ChunkRequestKind::DecodeError,
        ];
        let mut seen = std::collections::HashSet::new();
        for k in req {
            assert!(k.index() < ChunkRequestKind::N);
            assert!(seen.insert(k.index()));
        }
        let resp = [
            ChunkResponseKey::GetSuccess,
            ChunkResponseKey::GetNotFound,
            ChunkResponseKey::GetError,
            ChunkResponseKey::PutSuccess,
            ChunkResponseKey::PutAlreadyExists,
            ChunkResponseKey::PutPaymentRequired,
            ChunkResponseKey::PutError,
            ChunkResponseKey::Quote,
            ChunkResponseKey::MerkleQuote,
            ChunkResponseKey::QuoteV2,
            ChunkResponseKey::MerkleQuoteV2,
            ChunkResponseKey::Other,
        ];
        let mut seen = std::collections::HashSet::new();
        for k in resp {
            assert!(k.index() < ChunkResponseKey::N);
            assert!(seen.insert(k.index()));
        }
    }

    #[test]
    fn records_accumulate() {
        let before_b = RX_BYTES[ChunkRequestKind::Get.index()].load(Ordering::Relaxed);
        let before_c = RX_COUNT[ChunkRequestKind::Get.index()].load(Ordering::Relaxed);
        record_rx(ChunkRequestKind::Get, 40);
        record_rx(ChunkRequestKind::Get, 2);
        assert_eq!(
            RX_BYTES[ChunkRequestKind::Get.index()].load(Ordering::Relaxed),
            before_b + 42
        );
        assert_eq!(
            RX_COUNT[ChunkRequestKind::Get.index()].load(Ordering::Relaxed),
            before_c + 2
        );
        let before_t = TX_BYTES[ChunkResponseKey::GetSuccess.index()].load(Ordering::Relaxed);
        record_tx(ChunkResponseKey::GetSuccess, 4096);
        assert_eq!(
            TX_BYTES[ChunkResponseKey::GetSuccess.index()].load(Ordering::Relaxed),
            before_t + 4096
        );
    }
}
