//! Payment proof re-exports from [`ant_protocol`].
//!
//! Extracted to the [`ant_protocol`] crate in 0.11 so `ant-client` and
//! `ant-node` share one version of the serialization format. Internal
//! callers using `crate::payment::proof::…` keep working unchanged.

pub use ant_protocol::payment::proof::{
    deserialize_merkle_proof, deserialize_proof, detect_proof_type, serialize_merkle_proof,
    serialize_single_node_proof, PaymentProof, ProofType,
};
