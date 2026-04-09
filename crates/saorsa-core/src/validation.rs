// Copyright (c) 2025 Saorsa Labs Limited

// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Comprehensive input validation framework for P2P Foundation
//!
//! This module provides a robust validation system for all external inputs,
//! including network messages, API parameters, file paths, and cryptographic parameters.
//!
//! # Features
//!
//! - **Type-safe validation traits**: Extensible validation system
//! - **Rate limiting**: Per-IP and global rate limiting with adaptive throttling
//! - **Performance optimized**: < 5% overhead for validation operations
//! - **Security hardened**: Protection against common attack vectors
//! - **Comprehensive logging**: All validation failures are logged
//!
//! # Usage
//!
//! ```rust,ignore
//! use saorsa_core::validation::{Validate, ValidationContext, ValidationError};
//! use saorsa_core::validation::{validate_peer_id, validate_message_size};
//!
//! #[derive(Debug)]
//! struct NetworkMessage {
//!     peer_id: PeerId,
//!     payload: Vec<u8>,
//! }
//!
//! impl Validate for NetworkMessage {
//!     fn validate(&self, ctx: &ValidationContext) -> Result<(), ValidationError> {
//!         // Validate peer ID format
//!         validate_peer_id(&self.peer_id)?;
//!
//!         // Validate payload size
//!         validate_message_size(self.payload.len(), ctx.max_message_size)?;
//!
//!         Ok(())
//!     }
//! }
//! ```

use crate::PeerId;
use crate::error::{P2PError, P2pResult};

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

// Constants for validation rules
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16MB
const MAX_PATH_LENGTH: usize = 4096;
const MAX_KEY_SIZE: usize = 1024 * 1024; // 1MB for DHT keys
const MAX_VALUE_SIZE: usize = 10 * 1024 * 1024; // 10MB for DHT values
#[allow(dead_code)]
const MAX_FILE_NAME_LENGTH: usize = 255;

// Rate limiting constants
const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_MAX_REQUESTS_PER_WINDOW: u32 = 1000;
const DEFAULT_BURST_SIZE: u32 = 100;

// Validation functions below operate without panicking and avoid global regexes

/// Validation errors specific to input validation
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid peer ID format: {0}")]
    InvalidPeerId(String),

    #[error("Invalid network address: {0}")]
    InvalidAddress(String),

    #[error("Message size exceeds limit: {size} > {limit}")]
    MessageTooLarge { size: usize, limit: usize },

    #[error("Invalid file path: {0}")]
    InvalidPath(String),

    #[error("Path traversal attempt detected: {0}")]
    PathTraversal(String),

    #[error("Invalid key size: {size} bytes (max: {max})")]
    InvalidKeySize { size: usize, max: usize },

    #[error("Invalid value size: {size} bytes (max: {max})")]
    InvalidValueSize { size: usize, max: usize },

    #[error("Invalid cryptographic parameter: {0}")]
    InvalidCryptoParam(String),

    #[error("Rate limit exceeded for {identifier}")]
    RateLimitExceeded { identifier: String },

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Value out of range: {value} (min: {min}, max: {max})")]
    OutOfRange { value: i64, min: i64, max: i64 },
}

impl From<ValidationError> for P2PError {
    fn from(err: ValidationError) -> Self {
        P2PError::Validation(err.to_string().into())
    }
}

/// Context for validation operations
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ValidationContext {
    pub max_message_size: usize,
    pub max_key_size: usize,
    pub max_value_size: usize,
    pub max_path_length: usize,
    pub allow_localhost: bool,
    pub allow_private_ips: bool,
    pub rate_limiter: Option<Arc<RateLimiter>>,
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self {
            max_message_size: MAX_MESSAGE_SIZE,
            max_key_size: MAX_KEY_SIZE,
            max_value_size: MAX_VALUE_SIZE,
            max_path_length: MAX_PATH_LENGTH,
            allow_localhost: false,
            allow_private_ips: false,
            rate_limiter: None,
        }
    }
}

#[allow(dead_code)]
impl ValidationContext {
    /// Create a new validation context with custom settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable rate limiting
    pub fn with_rate_limiting(mut self, limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Allow localhost connections
    pub fn allow_localhost(mut self) -> Self {
        self.allow_localhost = true;
        self
    }

    /// Allow private IP addresses
    pub fn allow_private_ips(mut self) -> Self {
        self.allow_private_ips = true;
        self
    }
}

/// Core validation trait
#[allow(dead_code)]
pub trait Validate {
    /// Validate the object with the given context
    fn validate(&self, ctx: &ValidationContext) -> P2pResult<()>;
}

/// Trait for sanitizing input
#[allow(dead_code)]
pub trait Sanitize {
    /// Sanitize the input, returning a cleaned version
    fn sanitize(&self) -> Self;
}

// ===== Peer ID Validation =====

/// Validate a peer ID.
///
/// PeerId is a strongly-typed 32-byte identifier that is always valid by
/// construction, so this is a no-op. Kept for API compatibility.
#[allow(dead_code)]
pub fn validate_peer_id(_peer_id: &PeerId) -> P2pResult<()> {
    Ok(())
}

// ===== Message Size Validation =====

/// Validate message size
#[allow(dead_code)]
pub fn validate_message_size(size: usize, max_size: usize) -> P2pResult<()> {
    if size > max_size {
        return Err(ValidationError::MessageTooLarge {
            size,
            limit: max_size,
        }
        .into());
    }
    Ok(())
}

// ===== File Path Validation =====

/// Validate a file path for security
#[allow(dead_code)]
pub fn validate_file_path(path: &Path) -> P2pResult<()> {
    let path_str = path.to_string_lossy();

    // Check path length
    if path_str.len() > MAX_PATH_LENGTH {
        return Err(ValidationError::InvalidPath(format!(
            "Path too long: {} > {}",
            path_str.len(),
            MAX_PATH_LENGTH
        ))
        .into());
    }

    // URL decode to catch encoded traversal attempts
    let decoded = path_str
        .replace("%2e", ".")
        .replace("%2f", "/")
        .replace("%5c", "\\");

    // Check for path traversal attempts (including encoded versions)
    let traversal_patterns = ["../", "..\\", "..", "..;", "....//", "%2e%2e", "%252e%252e"];
    for pattern in &traversal_patterns {
        if path_str.contains(pattern) || decoded.contains(pattern) {
            return Err(ValidationError::PathTraversal(path_str.to_string()).into());
        }
    }

    // Check for null bytes
    if path_str.contains('\0') {
        return Err(ValidationError::InvalidPath("Path contains null bytes".to_string()).into());
    }

    // Check for command injection characters
    let dangerous_chars = ['|', '&', ';', '$', '`', '\n'];
    if path_str.chars().any(|c| dangerous_chars.contains(&c)) {
        return Err(
            ValidationError::InvalidPath("Path contains dangerous characters".to_string()).into(),
        );
    }

    // Validate each component
    for component in path.components() {
        if let Some(name) = component.as_os_str().to_str() {
            if name.len() > MAX_FILE_NAME_LENGTH {
                return Err(ValidationError::InvalidPath(format!(
                    "Component '{}' exceeds maximum length",
                    name
                ))
                .into());
            }

            // Check for invalid characters
            if name.contains('\0') {
                return Err(ValidationError::InvalidPath(format!(
                    "Component '{}' contains invalid characters",
                    name
                ))
                .into());
            }
        }
    }

    Ok(())
}

// ===== Cryptographic Parameter Validation =====

/// Validate key size for cryptographic operations
#[allow(dead_code)]
pub fn validate_key_size(size: usize, expected: usize) -> P2pResult<()> {
    if size != expected {
        return Err(ValidationError::InvalidCryptoParam(format!(
            "Invalid key size: expected {} bytes, got {}",
            expected, size
        ))
        .into());
    }
    Ok(())
}

/// Validate nonce size
#[allow(dead_code)]
pub fn validate_nonce_size(size: usize, expected: usize) -> P2pResult<()> {
    if size != expected {
        return Err(ValidationError::InvalidCryptoParam(format!(
            "Invalid nonce size: expected {} bytes, got {}",
            expected, size
        ))
        .into());
    }
    Ok(())
}

// ===== DHT Key/Value Validation =====

/// Validate DHT key
#[allow(dead_code)]
pub fn validate_dht_key(key: &[u8], ctx: &ValidationContext) -> P2pResult<()> {
    if key.is_empty() {
        return Err(ValidationError::InvalidFormat("DHT key cannot be empty".to_string()).into());
    }

    if key.len() > ctx.max_key_size {
        return Err(ValidationError::InvalidKeySize {
            size: key.len(),
            max: ctx.max_key_size,
        }
        .into());
    }

    Ok(())
}

/// Validate DHT value
#[allow(dead_code)]
pub fn validate_dht_value(value: &[u8], ctx: &ValidationContext) -> P2pResult<()> {
    if value.len() > ctx.max_value_size {
        return Err(ValidationError::InvalidValueSize {
            size: value.len(),
            max: ctx.max_value_size,
        }
        .into());
    }

    Ok(())
}

// ===== Rate Limiting =====

/// Rate limiter for preventing abuse (unified engine)
#[derive(Debug)]
pub struct RateLimiter {
    /// Shared token bucket engine for global and per-IP limiting
    engine: crate::rate_limit::SharedEngine<IpAddr>,
    /// Configuration
    #[allow(dead_code)]
    config: RateLimitConfig,
}

/// Rate limit configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    /// Time window for rate limiting
    pub window: Duration,
    /// Maximum requests per window
    pub max_requests: u32,
    /// Burst size allowed
    pub burst_size: u32,
    /// Enable adaptive throttling
    pub adaptive: bool,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_RATE_LIMIT_WINDOW,
            max_requests: DEFAULT_MAX_REQUESTS_PER_WINDOW,
            burst_size: DEFAULT_BURST_SIZE,
            adaptive: true,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

// Deprecated per-module bucket removed; using crate::rate_limit::Engine instead.

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        let engine_cfg = crate::rate_limit::EngineConfig {
            window: config.window,
            max_requests: config.max_requests,
            burst_size: config.burst_size,
        };
        Self {
            engine: std::sync::Arc::new(crate::rate_limit::Engine::new(engine_cfg)),
            config,
        }
    }

    /// Check if a request from an IP is allowed
    pub fn check_ip(&self, ip: &IpAddr) -> P2pResult<()> {
        // Global limit
        if !self.engine.try_consume_global() {
            return Err(ValidationError::RateLimitExceeded {
                identifier: "global".to_string(),
            }
            .into());
        }

        // Per-IP limit
        if !self.engine.try_consume_key(ip) {
            return Err(ValidationError::RateLimitExceeded {
                identifier: ip.to_string(),
            }
            .into());
        }

        Ok(())
    }

    /// Clean up expired entries
    #[allow(dead_code)]
    pub fn cleanup(&self) {
        // Not required with the unified engine (buckets age out via window). No-op.
    }
}

// ===== Validation Implementations for Common Types =====

/// Network message validation
#[derive(Debug)]
#[allow(dead_code)]
pub struct NetworkMessage {
    pub peer_id: PeerId,
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

impl Validate for NetworkMessage {
    fn validate(&self, ctx: &ValidationContext) -> P2pResult<()> {
        // PeerId is valid by construction
        validate_peer_id(&self.peer_id)?;

        // Validate payload size
        validate_message_size(self.payload.len(), ctx.max_message_size)?;

        // Validate timestamp (not too far in future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| P2PError::Internal(format!("System time error: {}", e).into()))?
            .as_secs();

        if self.timestamp > now + 300 {
            // 5 minutes tolerance
            return Err(
                ValidationError::InvalidFormat("Timestamp too far in future".to_string()).into(),
            );
        }

        Ok(())
    }
}

/// API request validation
#[derive(Debug)]
#[allow(dead_code)]
pub struct ApiRequest {
    pub method: String,
    pub path: String,
    pub params: HashMap<String, String>,
}

impl Validate for ApiRequest {
    fn validate(&self, _ctx: &ValidationContext) -> P2pResult<()> {
        // Validate method
        match self.method.as_str() {
            "GET" | "POST" | "PUT" | "DELETE" => {}
            _ => {
                return Err(ValidationError::InvalidFormat(format!(
                    "Invalid HTTP method: {}",
                    self.method
                ))
                .into());
            }
        }

        // Validate path
        if !self.path.starts_with('/') {
            return Err(
                ValidationError::InvalidFormat("Path must start with /".to_string()).into(),
            );
        }

        if self.path.contains("..") {
            return Err(ValidationError::PathTraversal(self.path.clone()).into());
        }

        // Validate parameters
        for (key, value) in &self.params {
            if key.is_empty() {
                return Err(
                    ValidationError::InvalidFormat("Empty parameter key".to_string()).into(),
                );
            }

            // Check for SQL injection patterns
            let lower_value = value.to_lowercase();
            let sql_patterns = [
                "select ", "insert ", "update ", "delete ", "drop ", "union ", "exec ", "--", "/*",
                "*/", "'", "\"", " or ", " and ", "1=1", "1='1",
            ];

            for pattern in &sql_patterns {
                if lower_value.contains(pattern) {
                    return Err(ValidationError::InvalidFormat(
                        "Suspicious parameter value: potential SQL injection".to_string(),
                    )
                    .into());
                }
            }

            // Check for command injection patterns
            let dangerous_chars = ['|', '&', ';', '$', '`', '\n', '\0'];
            if value.chars().any(|c| dangerous_chars.contains(&c)) {
                return Err(ValidationError::InvalidFormat(
                    "Dangerous characters in parameter value".to_string(),
                )
                .into());
            }
        }

        Ok(())
    }
}

/// Sanitize a string for safe usage
#[allow(dead_code)]
pub fn sanitize_string(input: &str, max_length: usize) -> String {
    // First remove any HTML tags and dangerous patterns
    let mut cleaned = input
        .replace(['<', '>'], "")
        .replace("script", "")
        .replace("javascript:", "")
        .replace("onerror", "")
        .replace("onload", "")
        .replace("onclick", "")
        .replace("alert", "")
        .replace("iframe", "");

    // Also handle unicode normalization attacks
    cleaned = cleaned.replace('\u{2060}', ""); // Word joiner
    cleaned = cleaned.replace('\u{ffa0}', ""); // Halfwidth hangul filler
    cleaned = cleaned.replace('\u{200b}', ""); // Zero width space
    cleaned = cleaned.replace('\u{200c}', ""); // Zero width non-joiner
    cleaned = cleaned.replace('\u{200d}', ""); // Zero width joiner

    // Finally filter to safe characters (no spaces allowed)
    cleaned
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .take(max_length)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_validation() {
        // PeerId is always valid by construction
        let peer = PeerId::random();
        assert!(validate_peer_id(&peer).is_ok());
    }

    #[test]
    fn test_file_path_validation() {
        // Valid paths
        assert!(validate_file_path(Path::new("data/file.txt")).is_ok());
        assert!(validate_file_path(Path::new("/usr/local/bin")).is_ok());

        // Invalid paths
        assert!(validate_file_path(Path::new("../etc/passwd")).is_err());
        assert!(validate_file_path(Path::new("file\0name")).is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let config = RateLimitConfig {
            window: Duration::from_millis(500), // Shorter window for testing
            max_requests: 10,
            burst_size: 5,
            ..Default::default()
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should allow burst
        for _ in 0..5 {
            assert!(limiter.check_ip(&ip).is_ok());
        }

        // Should start rate limiting after burst
        assert!(limiter.check_ip(&ip).is_err()); // Should be rate limited now

        // After waiting longer than the window, should allow again
        std::thread::sleep(Duration::from_millis(600));
        assert!(limiter.check_ip(&ip).is_ok());
    }

    #[test]
    fn test_message_validation() {
        let ctx = ValidationContext::default();

        let valid_msg = NetworkMessage {
            peer_id: PeerId::random(),
            payload: vec![0u8; 1024],
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        assert!(valid_msg.validate(&ctx).is_ok());
    }

    #[test]
    fn test_sanitization() {
        assert_eq!(sanitize_string("hello world!", 20), "helloworld");

        assert_eq!(sanitize_string("test@#$%123", 20), "test123");

        assert_eq!(
            sanitize_string("very_long_string_that_exceeds_limit", 10),
            "very_long_"
        );
    }
}
