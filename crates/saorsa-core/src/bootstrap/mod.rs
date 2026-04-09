// Copyright 2024 Saorsa Labs Limited
//
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

//! Bootstrap Cache System
//!
//! Provides decentralized peer discovery through local caching of known contacts.
//! Uses saorsa-transport's BootstrapCache internally with additional Sybil protection
//! via rate limiting and IP diversity enforcement.

pub mod cache;
pub mod manager;

// Re-export the primary BootstrapManager (wraps saorsa-transport)
pub use manager::BootstrapManager;
pub use manager::{BootstrapConfig, BootstrapStats};

// Re-export close group cache types
pub use cache::{CachedCloseGroupPeer, CloseGroupCache};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::NodeConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = BootstrapConfig {
            cache_dir: temp_dir.path().to_path_buf(),
            max_peers: 1000,
            ..BootstrapConfig::default()
        };
        let node_config = NodeConfig::default();

        let manager = BootstrapManager::with_node_config(config, &node_config).await;
        assert!(manager.is_ok());
    }
}
