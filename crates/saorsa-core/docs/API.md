# Saorsa Core API Reference

This document provides a comprehensive guide to the saorsa-core public API.

## Table of Contents

- [Phonebook & Trust Signals](#phonebook--trust-signals)
- [DHT Operations](#dht-operations)
- [Network & Transport](#network--transport)
- [Cryptography](#cryptography)
- [Trust & Reputation](#trust--reputation)
- [Bootstrap & Discovery](#bootstrap--discovery)
- [Configuration](#configuration)

---

## Phonebook & Trust Signals

saorsa-core uses the DHT strictly as a **peer phonebook** (routing + peer records).
Application data storage is handled in **saorsa-node** via `send_message`-style APIs.

To keep reputation accurate, saorsa-node reports data availability outcomes back to
saorsa-core’s trust engine:

```rust
use saorsa_core::adaptive::{EigenTrustEngine, NodeStatisticsUpdate};

// On successful data fetch:
trust_engine
    .update_node_stats(&peer_id, NodeStatisticsUpdate::CorrectResponse)
    .await;

// On failure:
trust_engine
    .update_node_stats(&peer_id, NodeStatisticsUpdate::FailedResponse)
    .await;
```

---

## Data Replication Flow (saorsa-node)

saorsa-core does **not** replicate application data. saorsa-node is responsible for:
1. Storing chunks locally and tracking replica sets.
2. Selecting target peers using saorsa-core’s adaptive routing outputs.
3. Replicating via `send_message` and updating trust based on outcomes.
4. Reacting to churn and re‑replicating when peers drop.

Recommended wiring (using `ReplicaPlanner`):
```rust
use saorsa_core::{
    adaptive::ReplicaPlanner,
    DhtNetworkManager,
};

// 1) Subscribe to churn signals
let planner = ReplicaPlanner::new(adaptive_dht, dht_manager);
let mut events = planner.subscribe_churn();
tokio::spawn(async move {
    while let Ok(event) = events.recv().await {
        if let saorsa_core::DhtNetworkEvent::PeerDisconnected { peer_id } = event {
            // saorsa-node should re-replicate any data that had replicas on peer_id
        }
    }
});

// 2) Choose replica targets (routing-only)
let targets = planner
    .select_replica_targets(content_hash, replica_count)
    .await?;

// 3) Replicate over send_message (saorsa-node chunk protocol)
// 4) Report success/failure back to EigenTrust
```

---

## DHT Operations

### DHT Network Manager

High-level DHT operations with network integration. Use this for **peer discovery**
and routing. Application data should travel over `send_message` in saorsa-node.

```rust
use saorsa_core::{DhtNetworkManager, DhtNetworkConfig, Key};

// Create manager
let config = DhtNetworkConfig::default();
let manager = DhtNetworkManager::new(config).await?;

// Find closest peers to a key (peer routing / phonebook lookups)
let key: Key = *blake3::hash(b\"peer-id\").as_bytes();
let peers = manager.find_closest_nodes(&key, 8).await?;
```

### AdaptiveDHT (Recommended)

Adaptive DHT for peer routing that enforces layered scoring (trust, geo, churn,
hyperbolic, SOM). Use this for **phonebook/routing**, not application data storage.

```rust
use saorsa_core::adaptive::{AdaptiveDHT, AdaptiveDhtConfig, AdaptiveDhtDependencies};
use saorsa_core::{DhtNetworkConfig, P2PNode};
use std::sync::Arc;

// Create your P2P node and DHT network config
let node = Arc::new(P2PNode::new(node_config).await?);
let dht_net = DhtNetworkConfig::default();

// Dependencies can be provided from your adaptive stack
let deps = AdaptiveDhtDependencies::with_defaults(identity, trust_provider);

// Attach AdaptiveDHT to the running node
let dht = AdaptiveDHT::attach_to_node(node, dht_net, AdaptiveDhtConfig::default(), deps).await?;

// Store and retrieve
let key = *blake3::hash(b\"example-key\").as_bytes();
dht.put(key, b\"example-value\".to_vec()).await?;
let value = dht.get(key).await?;
```

### Low-Level DHT

Direct DHT operations.

```rust
use saorsa_core::dht::{Key, Record, DHTConfig};

// Create key from bytes
let key: Key = *blake3::hash(b\"content-hash\").as_bytes();

// Create record
let record = Record::new(key, data, "peer-id".to_string());
```

### DHT Subscriptions

Watch for changes to DHT keys.

```rust
use saorsa_core::dht_watch;

let mut subscription = dht_watch(&key).await?;

while let Some(event) = subscription.recv().await {
    match event {
        DhtEvent::ValueChanged(new_value) => println!("Updated: {:?}", new_value),
        DhtEvent::Expired => println!("Key expired"),
    }
}
```

---

## Network & Transport

### P2P Node

Create and run a P2P node.

```rust
use saorsa_core::{P2PNode, NodeConfig};

// Using builder pattern
let config = NodeConfig::builder()
    .port(9000)
    .bootstrap_peer("192.168.1.1:9000".parse()?)
    .build()?;
let node = P2PNode::new(config).await?;

// Start the node
node.start().await?;
```

### Connection Events

Subscribe to connection events.

```rust
use saorsa_core::{subscribe_topology, TopologyEvent};

let mut subscription = subscribe_topology().await?;

while let Some(event) = subscription.recv().await {
    match event {
        TopologyEvent::PeerConnected(peer_id) => {
            println!("Connected: {}", peer_id);
        }
        TopologyEvent::PeerDisconnected(peer_id) => {
            println!("Disconnected: {}", peer_id);
        }
    }
}
```

---

## Cryptography

### Post-Quantum Key Generation

Generate ML-DSA-65 and ML-KEM-768 key pairs.

```rust
use saorsa_core::{MlDsa65, MlKem768, MlDsaOperations, MlKemOperations};

// Signature keypair (ML-DSA-65)
let (signing_pk, signing_sk) = MlDsa65::generate_keypair()?;

// Key exchange keypair (ML-KEM-768)
let (kem_pk, kem_sk) = MlKem768::generate_keypair()?;
```

### Digital Signatures

Sign and verify with ML-DSA-65.

```rust
use saorsa_core::{MlDsa65, MlDsaOperations};

// Sign message
let message = b"Hello, quantum-safe world!";
let signature = MlDsa65::sign(&signing_sk, message)?;

// Verify signature
let valid = MlDsa65::verify(&signing_pk, message, &signature)?;
assert!(valid);
```

### Key Encapsulation

Establish shared secrets with ML-KEM-768.

```rust
use saorsa_core::{MlKem768, MlKemOperations};

// Sender encapsulates
let (ciphertext, shared_secret_sender) = MlKem768::encapsulate(&recipient_pk)?;

// Recipient decapsulates
let shared_secret_recipient = MlKem768::decapsulate(&recipient_sk, &ciphertext)?;

// Both have the same shared secret
assert_eq!(shared_secret_sender, shared_secret_recipient);
```

### Symmetric Encryption

Encrypt data with ChaCha20-Poly1305.

```rust
use saorsa_core::{ChaCha20Poly1305Cipher, SymmetricKey};

// Create cipher with key
let key = SymmetricKey::generate();
let cipher = ChaCha20Poly1305Cipher::new(&key);

// Encrypt
let plaintext = b"Secret message";
let encrypted = cipher.encrypt(plaintext)?;

// Decrypt
let decrypted = cipher.decrypt(&encrypted)?;
assert_eq!(plaintext, &decrypted[..]);
```

### Secure Memory

Protect sensitive data in memory.

```rust
use saorsa_core::{SecureVec, SecureString, secure_vec_with_capacity};

// Secure vector (zeroed on drop)
let mut secret_key = secure_vec_with_capacity(32);
secret_key.extend_from_slice(&key_bytes);

// Secure string
let password = SecureString::from("my-secret-password");

// Memory is automatically zeroed when dropped
```

---

## Trust & Reputation

### EigenTrust Scores

Query reputation scores for peers via P2PNode.

```rust
// Get trust score (0.0 - 1.0)
let score = node.peer_trust(&peer_id);
```

### Node Age Verification

Check node age for privilege levels.

```rust
use saorsa_core::{NodeAgeVerifier, NodeAgeConfig, OperationType};

let verifier = NodeAgeVerifier::new(NodeAgeConfig::default());

// Check if node can perform operation
let result = verifier.verify_operation(&peer_id, OperationType::FullRouting)?;

match result {
    AgeVerificationResult::Allowed => println!("Operation permitted"),
    AgeVerificationResult::TooYoung { required_age } => {
        println!("Node must wait {} more seconds", required_age.as_secs());
    }
}
```

### IP Diversity Enforcement

Ensure geographic diversity.

```rust
use saorsa_core::{IPDiversityEnforcer, IPDiversityConfig};

let config = IPDiversityConfig {
    max_per_slash8: 0.25,   // Max 25% from any /8 subnet
    max_per_slash16: 0.10,  // Max 10% from any /16 subnet
    min_distinct_slash16: 5, // At least 5 distinct /16 subnets
};

let enforcer = IPDiversityEnforcer::new(config);

// Check if IP can be added
if enforcer.check_diversity(ip_addr) {
    // IP meets diversity requirements
}
```

---

## Bootstrap & Discovery

### Bootstrap Manager

Manage peer discovery cache.

```rust
use saorsa_core::{BootstrapManager, CacheConfig};
use std::path::PathBuf;

// Create with default config
let manager = BootstrapManager::new(PathBuf::from("~/.cache/saorsa")).await?;

// Add contact (with Sybil protection)
manager.add_contact("192.168.1.100:9000".parse()?).await?;

// Get bootstrap contacts
let contacts = manager.get_contacts(10).await;

// Record connection result
manager.record_connection_result(addr, true, Some(Duration::from_millis(50))).await;
```

### Bootstrap Configuration

Configure cache behavior.

```rust
use saorsa_core::bootstrap::CacheConfig;

let config = CacheConfig {
    cache_dir: PathBuf::from("~/.cache/saorsa"),
    max_contacts: 30_000,
    merge_interval: Duration::from_secs(60),
    cleanup_interval: Duration::from_secs(300),
    quality_update_interval: Duration::from_secs(60),
    stale_threshold: Duration::from_secs(86400),
    ..Default::default()
};
```

---

## Configuration

### Production Configuration

Configure for production deployment.

```rust
use saorsa_core::{ProductionConfig, Config};

let config = ProductionConfig {
    max_connections: 1000,
    max_memory_mb: 512,
    enable_metrics: true,
    metrics_port: 9090,
    ..Default::default()
};
```

### Health Monitoring

Enable health endpoints.

```rust
use saorsa_core::{HealthManager, HealthServer, PrometheusExporter};

// Create health manager
let health = HealthManager::new();

// Start health server
let server = HealthServer::new(health.clone());
server.start("0.0.0.0:8080").await?;

// Export Prometheus metrics
let exporter = PrometheusExporter::new(health);
let metrics = exporter.export()?;
```

### Rate Limiting

Configure join rate limits.

```rust
use saorsa_core::{JoinRateLimiter, JoinRateLimiterConfig};

let config = JoinRateLimiterConfig {
    per_ip_per_minute: 5,
    per_subnet24_per_minute: 20,
    per_subnet16_per_hour: 100,
    ..Default::default()
};

let limiter = JoinRateLimiter::new(config);

// Check rate limit
match limiter.check_rate(ip_addr) {
    Ok(()) => println!("Rate OK"),
    Err(e) => println!("Rate limited: {}", e),
}
```

---

## Error Handling

All operations return `Result<T, P2PError>`:

```rust
use saorsa_core::{DhtNetworkManager, P2PError, Result};

async fn example(manager: &DhtNetworkManager) -> Result<()> {
    let key = *blake3::hash(b"peer-id").as_bytes();
    let _peers = manager.find_closest_nodes(&key, 8).await.map_err(|e| {
        match e {
            P2PError::Timeout(_) => println!("Operation timed out"),
            P2PError::Network(e) => println!("Network error: {}", e),
            _ => println!("Other error: {}", e),
        }
        e
    })?;
    Ok(())
}
```

---

## Feature Flags

Enable optional features in `Cargo.toml`:

```toml
[dependencies]
saorsa-core = { version = "0.11", features = ["metrics"] }
```

| Feature | Description |
|---------|-------------|
| `metrics` | Prometheus metrics integration |

---

## Thread Safety

Most types are `Send + Sync` and can be shared across threads:

```rust
use std::sync::Arc;
use tokio::spawn;

let manager = Arc::new(DhtNetworkManager::new(config).await?);

let manager_clone = manager.clone();
spawn(async move {
    manager_clone.store(key, record).await?;
});
```

---

## Version Compatibility

| saorsa-core | saorsa-transport | Rust | Features |
|-------------|----------|------|----------|
| 0.11.x | 0.21.x | 1.75+ | Full PQC, placement system, threshold crypto |
| 0.10.x | 0.20.x | 1.75+ | Full PQC, unified config |
| 0.5.x | 0.14.x | 1.75+ | Legacy stable |

---

## See Also

- [Architecture Decision Records](./adr/) - Design decisions
- [Security Model](./SECURITY_MODEL.md) - Security architecture
- [Auto-Upgrade System](./AUTO_UPGRADE.md) - Binary updates
