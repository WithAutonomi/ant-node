// Copyright (c) 2025 Saorsa Labs Limited

// This file is part of the Saorsa P2P network.

// Licensed under the AGPL-3.0 license:
// <https://www.gnu.org/licenses/agpl-3.0.html>

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Copyright 2024 P2P Foundation
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Peer Identity
//!
//! Implements the core identity system for P2P nodes with:
//! - ML-DSA-65 post-quantum cryptographic keys
//! - Four-word human-readable addresses
//! - Deterministic generation from seeds

use crate::error::IdentityError;
use crate::{P2PError, Result};
use saorsa_pqc::HkdfSha3_256;
use saorsa_pqc::api::sig::{MlDsa, MlDsaVariant};
use saorsa_pqc::api::traits::Kdf;
use serde::{Deserialize, Serialize};
use std::fmt;

// Import PQC types from saorsa_transport via quantum_crypto module
use crate::quantum_crypto::saorsa_transport_integration::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
};

// Re-export canonical PeerId from the peer_id module.
pub use super::peer_id::{PEER_ID_BYTE_LEN, PeerId, PeerIdParseError};

/// Create a [`PeerId`] from an ML-DSA public key.
///
/// This is a standalone function because it depends on `MlDsaPublicKey`
/// from `saorsa-pqc`, which `saorsa-types` does not (and should not)
/// depend on.
pub fn peer_id_from_public_key(public_key: &MlDsaPublicKey) -> PeerId {
    let hash = blake3::hash(public_key.as_bytes());
    PeerId(*hash.as_bytes())
}

/// ML-DSA-65 public key length in bytes.
const ML_DSA_PUB_KEY_LEN: usize = 1952;

/// Create a [`PeerId`] from raw ML-DSA public key bytes.
///
/// # Errors
///
/// Returns an error if the byte slice is not exactly 1952 bytes or
/// cannot be parsed as a valid ML-DSA-65 public key.
pub fn peer_id_from_public_key_bytes(bytes: &[u8]) -> Result<PeerId> {
    if bytes.len() != ML_DSA_PUB_KEY_LEN {
        return Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Invalid ML-DSA public key length".to_string().into(),
        )));
    }

    let public_key = MlDsaPublicKey::from_bytes(bytes).map_err(|e| {
        IdentityError::InvalidFormat(format!("Invalid ML-DSA public key: {:?}", e).into())
    })?;

    Ok(peer_id_from_public_key(&public_key))
}

/// Public node identity information (without secret keys) - safe to clone
#[derive(Clone)]
pub struct PublicNodeIdentity {
    /// ML-DSA public key
    public_key: MlDsaPublicKey,
    /// Peer ID derived from public key
    peer_id: PeerId,
}

impl PublicNodeIdentity {
    /// Get peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    // Word addresses are not part of identity; use bootstrap/transport layers
}

/// Core node identity with cryptographic keys
///
/// `Debug` is manually implemented to redact secret key material.
pub struct NodeIdentity {
    /// ML-DSA-65 secret key (private)
    secret_key: MlDsaSecretKey,
    /// ML-DSA-65 public key
    public_key: MlDsaPublicKey,
    /// Peer ID derived from public key
    peer_id: PeerId,
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("peer_id", &self.peer_id)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

impl NodeIdentity {
    /// Generate new identity
    pub fn generate() -> Result<Self> {
        // Generate ML-DSA-65 key pair (saorsa-transport integration)
        let (public_key, secret_key) =
            crate::quantum_crypto::generate_ml_dsa_keypair().map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Failed to generate ML-DSA key pair: {}", e).into(),
                ))
            })?;

        let peer_id = peer_id_from_public_key(&public_key);

        Ok(Self {
            secret_key,
            public_key,
            peer_id,
        })
    }

    /// Generate from seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        // Derive a 32-byte ML-DSA seed from the input via HKDF-SHA3
        let mut xi = [0u8; 32];
        HkdfSha3_256::derive(seed, None, b"saorsa-node-identity-seed", &mut xi).map_err(|_| {
            P2PError::Identity(IdentityError::InvalidFormat("HKDF expand failed".into()))
        })?;

        // Generate a real ML-DSA-65 keypair deterministically from the seed
        let dsa = MlDsa::new(MlDsaVariant::MlDsa65);
        let (pk, sk) = dsa.generate_keypair_from_seed(&xi);

        let public_key = MlDsaPublicKey::from_bytes(&pk.to_bytes()).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("Invalid ML-DSA public key bytes: {e}").into(),
            ))
        })?;
        let secret_key = MlDsaSecretKey::from_bytes(&sk.to_bytes()).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("Invalid ML-DSA secret key bytes: {e}").into(),
            ))
        })?;

        let peer_id = peer_id_from_public_key(&public_key);

        Ok(Self {
            secret_key,
            public_key,
            peer_id,
        })
    }

    /// Get peer ID
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get public key
    pub fn public_key(&self) -> &MlDsaPublicKey {
        &self.public_key
    }

    // No Proof-of-Work in this crate

    /// Get secret key bytes (for raw key authentication)
    pub fn secret_key_bytes(&self) -> &[u8] {
        self.secret_key.as_bytes()
    }

    /// Clone the underlying ML-DSA-65 keypair.
    ///
    /// Used to install the node's identity as the transport's TLS keypair so
    /// that the SPKI carried in the QUIC handshake authenticates the same
    /// peer ID that signs application messages. Without this, the
    /// transport-level and application-level identities are distinct and
    /// must be reconciled by a wire-level handshake.
    pub fn clone_keypair(&self) -> (MlDsaPublicKey, MlDsaSecretKey) {
        (self.public_key.clone(), self.secret_key.clone())
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        crate::quantum_crypto::ml_dsa_sign(&self.secret_key, message).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("ML-DSA signing failed: {:?}", e).into(),
            ))
        })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool> {
        crate::quantum_crypto::ml_dsa_verify(&self.public_key, message, signature).map_err(|e| {
            P2PError::Identity(IdentityError::InvalidFormat(
                format!("ML-DSA verification failed: {:?}", e).into(),
            ))
        })
    }

    /// Create a public version of this identity (safe to clone)
    pub fn to_public(&self) -> PublicNodeIdentity {
        PublicNodeIdentity {
            public_key: self.public_key.clone(),
            peer_id: self.peer_id,
        }
    }
}

impl NodeIdentity {
    /// Create an identity from an existing secret key
    /// Note: Currently not supported as saorsa-transport doesn't provide public key derivation from secret key
    /// This would require storing both keys together
    pub fn from_secret_key(_secret_key: MlDsaSecretKey) -> Result<Self> {
        Err(P2PError::Identity(IdentityError::InvalidFormat(
            "Creating identity from secret key alone is not supported"
                .to_string()
                .into(),
        )))
    }
}

impl NodeIdentity {
    /// Save identity to a JSON file (async)
    pub async fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        use tokio::fs;
        let data = self.export();
        let json = serde_json::to_string_pretty(&data).map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to serialize identity: {}", e).into(),
            ))
        })?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to create directory: {}", e).into(),
                ))
            })?;
        }

        tokio::fs::write(path, json).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to write identity file: {}", e).into(),
            ))
        })?;
        Ok(())
    }

    /// Load identity from a JSON file (async)
    pub async fn load_from_file(path: &std::path::Path) -> Result<Self> {
        let json = tokio::fs::read_to_string(path).await.map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to read identity file: {}", e).into(),
            ))
        })?;
        let data: IdentityData = serde_json::from_str(&json).map_err(|e| {
            P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                format!("Failed to deserialize identity: {}", e).into(),
            ))
        })?;
        Self::import(&data)
    }
}

/// Serializable identity data for persistence
#[derive(Serialize, Deserialize)]
pub struct IdentityData {
    /// ML-DSA secret key bytes (4032 bytes for ML-DSA-65)
    pub secret_key: Vec<u8>,
    /// ML-DSA public key bytes (1952 bytes for ML-DSA-65)
    pub public_key: Vec<u8>,
}

impl NodeIdentity {
    /// Export identity for persistence
    pub fn export(&self) -> IdentityData {
        IdentityData {
            secret_key: self.secret_key.as_bytes().to_vec(),
            public_key: self.public_key.as_bytes().to_vec(),
        }
    }

    /// Import identity from persisted data
    pub fn import(data: &IdentityData) -> Result<Self> {
        // Reconstruct keys from bytes
        let secret_key =
            crate::quantum_crypto::saorsa_transport_integration::MlDsaSecretKey::from_bytes(
                &data.secret_key,
            )
            .map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Invalid ML-DSA secret key: {e}").into(),
                ))
            })?;
        let public_key =
            crate::quantum_crypto::saorsa_transport_integration::MlDsaPublicKey::from_bytes(
                &data.public_key,
            )
            .map_err(|e| {
                P2PError::Identity(IdentityError::InvalidFormat(
                    format!("Invalid ML-DSA public key: {e}").into(),
                ))
            })?;

        let peer_id = peer_id_from_public_key(&public_key);

        Ok(Self {
            secret_key,
            public_key,
            peer_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_generation() {
        let (public_key, _secret_key) = crate::quantum_crypto::generate_ml_dsa_keypair()
            .expect("ML-DSA key generation should succeed");
        let peer_id = peer_id_from_public_key(&public_key);

        // Should be 32 bytes
        assert_eq!(peer_id.to_bytes().len(), 32);

        // Should be deterministic
        let peer_id2 = peer_id_from_public_key(&public_key);
        assert_eq!(peer_id, peer_id2);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = PeerId([0u8; 32]);
        let mut id2_bytes = [0u8; 32];
        id2_bytes[0] = 0xFF;
        let id2 = PeerId(id2_bytes);

        let distance = id1.xor_distance(&id2);
        assert_eq!(distance[0], 0xFF);
        for byte in &distance[1..] {
            assert_eq!(*byte, 0);
        }
    }

    #[test]
    fn test_proof_of_work() {
        // PoW removed: this test no longer applicable
    }

    #[test]
    fn test_identity_generation() {
        let identity = NodeIdentity::generate().expect("Identity generation should succeed");

        // Test signing and verification
        let message = b"Hello, P2P!";
        let signature = identity.sign(message).unwrap();
        assert!(identity.verify(message, &signature).unwrap());

        // Wrong message should fail with original signature
        assert!(!identity.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_deterministic_generation() {
        let seed = [0x42; 32];
        let identity1 = NodeIdentity::from_seed(&seed).expect("Identity from seed should succeed");
        let identity2 = NodeIdentity::from_seed(&seed).expect("Identity from seed should succeed");

        // Should generate same identity
        assert_eq!(identity1.peer_id, identity2.peer_id);
        assert_eq!(
            identity1.public_key().as_bytes(),
            identity2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_identity_persistence() {
        let identity = NodeIdentity::generate().expect("Identity generation should succeed");

        // Export
        let data = identity.export();

        // Import
        let imported = NodeIdentity::import(&data).expect("Import should succeed with valid data");

        // Should be the same
        assert_eq!(identity.peer_id, imported.peer_id);
        assert_eq!(
            identity.public_key().as_bytes(),
            imported.public_key().as_bytes()
        );

        // Should be able to sign with imported identity
        let message = b"Test message";
        let signature = imported.sign(message);
        assert!(identity.verify(message, &signature.unwrap()).unwrap());
    }

    #[test]
    fn test_peer_id_display_full_hex() {
        let id = PeerId([0xAB; 32]);
        let display = format!("{}", id);
        assert_eq!(display.len(), 64);
        assert_eq!(display, "ab".repeat(32));
    }

    #[test]
    fn test_peer_id_ord() {
        let a = PeerId([0x00; 32]);
        let b = PeerId([0xFF; 32]);
        assert!(a < b);
    }

    #[test]
    fn test_peer_id_from_str() {
        let hex = "ab".repeat(32);
        let id: PeerId = hex.parse().expect("should parse valid hex");
        assert_eq!(id.0, [0xAB; 32]);
    }

    #[test]
    fn test_peer_id_json_roundtrip() {
        let id = PeerId([0xAB; 32]);
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, format!("\"{}\"", "ab".repeat(32)));
        let deserialized: PeerId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_peer_id_postcard_roundtrip() {
        let id = PeerId([0xAB; 32]);
        let bytes = postcard::to_stdvec(&id).expect("serialize");
        let deserialized: PeerId = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(id, deserialized);
    }
}
