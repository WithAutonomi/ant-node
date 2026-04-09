// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! Integration with saorsa-transport's post-quantum cryptography
//!
//! This module provides integration with saorsa-transport's post-quantum
//! cryptography features, making them available to saorsa-core applications.

use anyhow::Result;
use once_cell::sync::Lazy;

// Re-export key saorsa-transport PQC types from types module
// Note: saorsa-transport 0.14+ is pure PQC only (no hybrid mode)
pub use saorsa_transport::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};

// Re-export ML-DSA algorithm implementation
pub use saorsa_transport::crypto::pqc::MlDsa65;

// Re-export PQC trait for ML-DSA operations
pub use saorsa_transport::crypto::pqc::MlDsaOperations;

static ML_DSA: Lazy<MlDsa65> = Lazy::new(MlDsa65::new);

/// Generate ML-DSA-65 key pair using saorsa-transport's implementation
pub fn generate_ml_dsa_keypair() -> Result<(MlDsaPublicKey, MlDsaSecretKey)> {
    let (public_key, secret_key) = ML_DSA
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("Failed to generate ML-DSA keypair: {}", e))?;
    Ok((public_key, secret_key))
}

/// Sign a message using ML-DSA-65 with saorsa-transport's implementation
pub fn ml_dsa_sign(secret_key: &MlDsaSecretKey, message: &[u8]) -> Result<MlDsaSignature> {
    ML_DSA
        .sign(secret_key, message)
        .map_err(|e| anyhow::anyhow!("Failed to sign with ML-DSA: {}", e))
}

/// Verify a signature using ML-DSA-65 with saorsa-transport's implementation
pub fn ml_dsa_verify(
    public_key: &MlDsaPublicKey,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    match ML_DSA.verify(public_key, message, signature) {
        Ok(is_valid) => Ok(is_valid),
        Err(e) => Err(anyhow::anyhow!("ML-DSA verification failed: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_roundtrip() {
        let keypair = generate_ml_dsa_keypair();
        assert!(keypair.is_ok(), "Should generate ML-DSA keypair");

        let (public_key, secret_key) = keypair.unwrap();
        let message = b"test message for ML-DSA";

        let signature = ml_dsa_sign(&secret_key, message);
        assert!(signature.is_ok(), "Should sign message with ML-DSA");

        let sig = signature.unwrap();
        let verification = ml_dsa_verify(&public_key, message, &sig);
        assert!(verification.is_ok(), "Should verify ML-DSA signature");
        assert!(verification.unwrap(), "Signature should be valid");
    }
}
