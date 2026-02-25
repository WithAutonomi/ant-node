//! Test harness that orchestrates the test network and EVM testnet.
//!
//! The `TestHarness` provides a unified interface for E2E tests, managing
//! both the saorsa node network and optional Anvil EVM testnet.

use super::anvil::TestAnvil;
use super::testnet::{TestNetwork, TestNetworkConfig, TestNode};
use saorsa_core::P2PNode;
use std::sync::Arc;
use tracing::info;

/// Error type for test harness operations.
#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    /// Testnet error
    #[error("Testnet error: {0}")]
    Testnet(#[from] super::testnet::TestnetError),

    /// Anvil error
    #[error("Anvil error: {0}")]
    Anvil(String),

    /// Node not found
    #[error("Node not found: index {0}")]
    NodeNotFound(usize),
}

/// Result type for harness operations.
pub type Result<T> = std::result::Result<T, HarnessError>;

/// Test harness that manages the complete test environment.
///
/// The harness coordinates:
/// - A network of 25 saorsa nodes
/// - Optional Anvil EVM testnet for payment verification
/// - Helper methods for common test operations
pub struct TestHarness {
    /// The test network.
    network: TestNetwork,

    /// Optional Anvil EVM testnet.
    anvil: Option<TestAnvil>,
}

impl TestHarness {
    /// Create and start a test network with default configuration (25 nodes).
    ///
    /// This is the standard setup for most E2E tests.
    ///
    /// # Errors
    ///
    /// Returns an error if the network fails to start.
    pub async fn setup() -> Result<Self> {
        Self::setup_with_config(TestNetworkConfig::default()).await
    }

    /// Create and start a test network with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The network configuration to use
    ///
    /// # Errors
    ///
    /// Returns an error if the network fails to start.
    pub async fn setup_with_config(config: TestNetworkConfig) -> Result<Self> {
        info!("Setting up test harness with {} nodes", config.node_count);

        let mut network = TestNetwork::new(config).await?;
        network.start().await?;

        Ok(Self {
            network,
            anvil: None,
        })
    }

    /// Create and start a minimal test network (5 nodes) for quick tests.
    ///
    /// # Errors
    ///
    /// Returns an error if the network fails to start.
    pub async fn setup_minimal() -> Result<Self> {
        Self::setup_with_config(TestNetworkConfig::minimal()).await
    }

    /// Create and start a small test network (10 nodes).
    ///
    /// # Errors
    ///
    /// Returns an error if the network fails to start.
    pub async fn setup_small() -> Result<Self> {
        Self::setup_with_config(TestNetworkConfig::small()).await
    }

    /// Create and start a test network with Anvil EVM testnet.
    ///
    /// Use this for tests that require payment verification.
    ///
    /// # Errors
    ///
    /// Returns an error if the network or Anvil fails to start.
    pub async fn setup_with_evm() -> Result<Self> {
        Self::setup_with_evm_and_config(TestNetworkConfig::default()).await
    }

    /// Create and start a test network with Anvil EVM testnet (alias for `setup_with_evm`).
    ///
    /// Use this for tests that require payment verification.
    ///
    /// # Errors
    ///
    /// Returns an error if the network or Anvil fails to start.
    pub async fn setup_with_payments() -> Result<Self> {
        Self::setup_with_evm().await
    }

    /// Create and start a test network with Anvil EVM testnet and custom config.
    ///
    /// # Arguments
    ///
    /// * `config` - The network configuration to use
    ///
    /// # Errors
    ///
    /// Returns an error if the network or Anvil fails to start.
    pub async fn setup_with_evm_and_config(config: TestNetworkConfig) -> Result<Self> {
        info!(
            "Setting up test harness with {} nodes and Anvil EVM",
            config.node_count
        );

        let mut network = TestNetwork::new(config).await?;
        network.start().await?;

        let anvil = TestAnvil::new()
            .await
            .map_err(|e| HarnessError::Anvil(format!("Failed to start Anvil: {e}")))?;

        Ok(Self {
            network,
            anvil: Some(anvil),
        })
    }

    /// Access the test network.
    #[must_use]
    pub fn network(&self) -> &TestNetwork {
        &self.network
    }

    /// Access the test network mutably.
    #[must_use]
    pub fn network_mut(&mut self) -> &mut TestNetwork {
        &mut self.network
    }

    /// Access the Anvil EVM testnet.
    #[must_use]
    pub fn anvil(&self) -> Option<&TestAnvil> {
        self.anvil.as_ref()
    }

    /// Check if EVM testnet is available.
    #[must_use]
    pub fn has_evm(&self) -> bool {
        self.anvil.is_some()
    }

    /// Access a specific node's P2P interface.
    ///
    /// # Arguments
    ///
    /// * `index` - The node index (0-based)
    ///
    /// # Returns
    ///
    /// The P2P node if found and running, None otherwise.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<Arc<P2PNode>> {
        self.network.node(index)?.p2p_node.clone()
    }

    /// Access a specific test node.
    ///
    /// # Arguments
    ///
    /// * `index` - The node index (0-based)
    #[must_use]
    pub fn test_node(&self, index: usize) -> Option<&TestNode> {
        self.network.node(index)
    }

    /// Access a specific test node mutably.
    ///
    /// # Arguments
    ///
    /// * `index` - The node index (0-based)
    #[must_use]
    pub fn test_node_mut(&mut self, index: usize) -> Option<&mut TestNode> {
        self.network.node_mut(index)
    }

    /// Get a random non-bootstrap node.
    ///
    /// Useful for tests that need to pick an arbitrary regular node.
    #[must_use]
    pub fn random_node(&self) -> Option<Arc<P2PNode>> {
        use rand::seq::SliceRandom;

        let regular_nodes: Vec<_> = self
            .network
            .regular_nodes()
            .iter()
            .filter(|n| n.p2p_node.is_some())
            .collect();

        regular_nodes
            .choose(&mut rand::thread_rng())
            .and_then(|n| n.p2p_node.clone())
    }

    /// Get a random bootstrap node.
    #[must_use]
    pub fn random_bootstrap_node(&self) -> Option<Arc<P2PNode>> {
        use rand::seq::SliceRandom;

        let bootstrap_nodes: Vec<_> = self
            .network
            .bootstrap_nodes()
            .iter()
            .filter(|n| n.p2p_node.is_some())
            .collect();

        bootstrap_nodes
            .choose(&mut rand::thread_rng())
            .and_then(|n| n.p2p_node.clone())
    }

    /// Get all P2P nodes.
    #[must_use]
    pub fn all_nodes(&self) -> Vec<Arc<P2PNode>> {
        self.network
            .nodes()
            .iter()
            .filter_map(|n| n.p2p_node.clone())
            .collect()
    }

    /// Get the total number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.network.node_count()
    }

    /// Check if the network is ready.
    pub async fn is_ready(&self) -> bool {
        self.network.is_ready().await
    }

    /// Get total connections across all nodes.
    pub async fn total_connections(&self) -> usize {
        self.network.total_connections().await
    }

    /// Teardown the test harness.
    ///
    /// This shuts down all nodes and the Anvil testnet if running.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    pub async fn teardown(mut self) -> Result<()> {
        info!("Tearing down test harness");

        // Shutdown network first
        self.network.shutdown().await?;

        // Shutdown Anvil if running
        if let Some(mut anvil) = self.anvil.take() {
            anvil.shutdown().await;
        }

        info!("Test harness teardown complete");
        Ok(())
    }
}

/// Macro for setting up and tearing down test networks.
///
/// This macro handles the boilerplate of creating a test harness,
/// running the test body, and ensuring cleanup happens.
///
/// # Example
///
/// ```rust,ignore
/// with_test_network!(harness, {
///     let node = harness.node(0).unwrap();
///     // Run test assertions...
///     Ok(())
/// });
/// ```
#[macro_export]
macro_rules! with_test_network {
    ($harness:ident, $body:block) => {{
        let $harness = $crate::tests::e2e::TestHarness::setup().await?;
        let result: Result<(), Box<dyn std::error::Error>> = async { $body }.await;
        $harness.teardown().await?;
        result
    }};
    ($harness:ident, $config:expr, $body:block) => {{
        let $harness = $crate::tests::e2e::TestHarness::setup_with_config($config).await?;
        let result: Result<(), Box<dyn std::error::Error>> = async { $body }.await;
        $harness.teardown().await?;
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_harness_error_display() {
        let err = HarnessError::NodeNotFound(5);
        assert!(err.to_string().contains('5'));
    }
}
