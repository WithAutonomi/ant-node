// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses


//! Standardized Error Handling Patterns for saorsa-transport
//!
//! This module provides consistent error handling patterns and utilities
//! to ensure uniform error propagation and handling across the codebase.

use std::fmt;
use thiserror::Error;

/// Comprehensive error type for saorsa-transport operations
#[derive(Error, Debug)]
pub enum SaorsaTransportError {
    /// Transport-level errors (connection issues, protocol violations)
    #[error("Transport error: {0}")]
    Transport(#[from] crate::transport_error::Error),

    /// Connection establishment errors
    #[error("Connection error: {0}")]
    Connection(#[from] crate::connection::ConnectionError),

    /// Network address discovery errors
    #[error("Discovery error: {0}")]
    Discovery(#[from] crate::candidate_discovery::DiscoveryError),

    /// NAT traversal errors
    #[error("NAT traversal error: {0}")]
    NatTraversal(#[from] crate::nat_traversal_api::NatTraversalError),

    /// Configuration validation errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// I/O operation errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic operation errors
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Post-Quantum Cryptography errors
    #[error("PQC error: {0}")]
    Pqc(#[from] crate::crypto::pqc::types::PqcError),

    /// Timeout errors
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Resource exhaustion errors
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Invalid input parameters
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Internal errors (should not happen in production)
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type alias for saorsa-transport operations
pub type Result<T> = std::result::Result<T, SaorsaTransportError>;

/// Error handling utilities
pub mod utils {
    use super::*;
    use tracing::{error, warn, info, debug};

    /// Log an error with appropriate level based on severity
    pub fn log_error<E: std::error::Error>(error: &E, context: &str) {
        let error_msg = format!("{}: {}", context, error);
        match error.downcast_ref::<SaorsaTransportError>() {
            Some(SaorsaTransportError::Internal(_)) => error!("{}", error_msg),
            Some(SaorsaTransportError::Transport(_)) => warn!("{}", error_msg),
            Some(SaorsaTransportError::Connection(_)) => warn!("{}", error_msg),
            Some(SaorsaTransportError::Timeout(_)) => info!("{}", error_msg),
            Some(SaorsaTransportError::InvalidParameter(_)) => debug!("{}", error_msg),
            _ => warn!("{}", error_msg),
        }
    }

    /// Convert an error to a user-friendly message
    pub fn to_user_message<E: std::error::Error>(error: &E) -> String {
        match error.downcast_ref::<SaorsaTransportError>() {
            Some(SaorsaTransportError::Transport(_)) => "Network connection error. Please check your internet connection.".to_string(),
            Some(SaorsaTransportError::Connection(_)) => "Failed to establish connection. The remote peer may be unreachable.".to_string(),
            Some(SaorsaTransportError::Discovery(_)) => "Failed to discover network configuration. Please check your network settings.".to_string(),
            Some(SaorsaTransportError::NatTraversal(_)) => "NAT traversal failed. This may be due to restrictive network policies.".to_string(),
            Some(SaorsaTransportError::Timeout(_)) => "Operation timed out. Please try again.".to_string(),
            Some(SaorsaTransportError::Config(_)) => "Configuration error. Please check your settings.".to_string(),
            Some(SaorsaTransportError::Io(_)) => "System I/O error. Please check file permissions and disk space.".to_string(),
            Some(SaorsaTransportError::Crypto(_)) => "Cryptographic operation failed. This may indicate a security issue.".to_string(),
            Some(SaorsaTransportError::Pqc(_)) => "Post-quantum cryptographic operation failed.".to_string(),
            Some(SaorsaTransportError::ResourceExhausted(_)) => "System resources exhausted. Please close some applications and try again.".to_string(),
            Some(SaorsaTransportError::InvalidParameter(_)) => "Invalid input parameters provided.".to_string(),
            Some(SaorsaTransportError::Internal(_)) => "An internal error occurred. Please report this issue.".to_string(),
            _ => format!("An unexpected error occurred: {}", error),
        }
    }

    /// Check if an error is recoverable
    pub fn is_recoverable<E: std::error::Error>(error: &E) -> bool {
        match error.downcast_ref::<SaorsaTransportError>() {
            Some(SaorsaTransportError::Timeout(_)) => true,
            Some(SaorsaTransportError::Connection(_)) => true,
            Some(SaorsaTransportError::Discovery(_)) => true,
            Some(SaorsaTransportError::NatTraversal(_)) => true,
            Some(SaorsaTransportError::Io(io_err)) => {
                // Some I/O errors are recoverable
                matches!(io_err.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted)
            }
            _ => false,
        }
    }

    /// Get recommended retry delay for an error
    pub fn get_retry_delay<E: std::error::Error>(error: &E) -> Option<std::time::Duration> {
        match error.downcast_ref::<SaorsaTransportError>() {
            Some(SaorsaTransportError::Timeout(_)) => Some(std::time::Duration::from_millis(100)),
            Some(SaorsaTransportError::Connection(_)) => Some(std::time::Duration::from_millis(500)),
            Some(SaorsaTransportError::Discovery(_)) => Some(std::time::Duration::from_secs(1)),
            Some(SaorsaTransportError::NatTraversal(_)) => Some(std::time::Duration::from_secs(2)),
            Some(SaorsaTransportError::Io(io_err)) => {
                match io_err.kind() {
                    std::io::ErrorKind::TimedOut => Some(std::time::Duration::from_millis(100)),
                    std::io::ErrorKind::Interrupted => Some(std::time::Duration::from_millis(10)),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// Error handling macros for consistent error propagation
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $error:expr) => {
        if !($condition) {
            return Err($error.into());
        }
    };
}

#[macro_export]
macro_rules! bail {
    ($error:expr) => {
        return Err($error.into());
    };
}

#[macro_export]
macro_rules! context {
    ($result:expr, $context:expr) => {
        $result.map_err(|e| SaorsaTransportError::Internal(format!("{}: {}", $context, e)))
    };
}

/// Best practices for error handling:
///
/// 1. **Use Result<T, E> everywhere**: Never use unwrap() or expect() in production code
/// 2. **Chain errors with ? operator**: Let errors bubble up naturally
/// 3. **Add context when needed**: Use context! macro to add context to errors
/// 4. **Handle recoverable errors**: Use is_recoverable() to determine if retry is appropriate
/// 5. **Log errors appropriately**: Use log_error() for consistent error logging
/// 6. **Provide user-friendly messages**: Use to_user_message() for end-user communication
/// 7. **Use specific error types**: Prefer specific error variants over generic ones
/// 8. **Document error conditions**: Document when and why errors can occur
/// 9. **Test error paths**: Ensure error conditions are tested
/// 10. **Fail securely**: Don't leak sensitive information in error messages
///
/// Example usage:
///
/// ```rust
/// use crate::error_handling::{SaorsaTransportError, Result, utils::*};
///
/// fn connect_to_peer(peer_id: &str) -> Result<()> {
///     // Validate input
///     ensure!(!peer_id.is_empty(), SaorsaTransportError::InvalidParameter("peer_id cannot be empty".to_string()));
///
///     // Attempt connection
///     match do_connection_attempt(peer_id) {
///         Ok(()) => Ok(()),
///         Err(e) => {
///             log_error(&e, "Failed to connect to peer");
///             if is_recoverable(&e) {
///                 if let Some(delay) = get_retry_delay(&e) {
///                     std::thread::sleep(delay);
///                     // Retry logic here
///                 }
///             }
///             Err(e)
///         }
///     }
/// }
/// ```