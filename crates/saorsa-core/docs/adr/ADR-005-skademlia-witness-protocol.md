# ADR-005: S/Kademlia Witness Protocol

## Status

Superseded

> **Note (2026-03):** The witness-based storage protocol described here was removed
> as part of the DHT phonebook cleanup. The DHT is now a **peer phonebook only**
> (routing, discovery, liveness). Data storage and replication are handled by the
> application layer (saorsa-node). S/Kademlia routing extensions (disjoint paths,
> Sybil detection, authenticated sibling broadcast) have also been removed. The
> codebase now uses standard Kademlia routing with a response-rate trust system
> for peer blocking.

## Context

Standard Kademlia DHT provides no protection against Byzantine nodes:

- **Eclipse attacks**: Malicious nodes surround a target, controlling its view of the network
- **Sybil attacks**: Adversary creates many identities to dominate key regions
- **Data corruption**: Malicious nodes return incorrect or modified data
- **Routing manipulation**: Adversaries direct queries to compromised nodes

The original Kademlia paper assumes honest participants—an assumption that fails in adversarial P2P environments.

### S/Kademlia Enhancements

The S/Kademlia paper (2007) proposed several mitigations:

1. **Crypto puzzles for node IDs**: Expensive ID generation limits Sybil attacks
2. **Sibling broadcast**: Queries sent to multiple closest nodes
3. **Disjoint lookup paths**: Parallel queries through different routes

However, S/Kademlia alone doesn't provide:
- Consensus on correct values
- Proof of honest storage
- Geographic diversity requirements

## Decision

We implement an **enhanced S/Kademlia protocol with witness-based validation**, combining:

1. **Kademlia routing** with K=8 replication
2. **Witness nodes** that attest to DHT operations
3. **Geographic diversity** requirements for witnesses
4. **Byzantine fault tolerance** via quorum consensus

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        DHT Operation                             │
│              STORE(key, value) or GET(key)                       │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Witness Selection                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ 1. Find K closest nodes to key                            │  │
│  │ 2. Filter by EigenTrust reputation (τ > 0.3)              │  │
│  │ 3. Ensure geographic diversity (≥3 regions)               │  │
│  │ 4. Select W witnesses (default W=3)                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────┬───────────────────────┘
                                          │
                                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Parallel Witness Queries                      │
│                                                                  │
│    ┌─────────┐      ┌─────────┐      ┌─────────┐               │
│    │Witness 1│      │Witness 2│      │Witness 3│               │
│    │(Europe) │      │(Americas)│     │(Asia)   │               │
│    └────┬────┘      └────┬────┘      └────┬────┘               │
│         │                │                │                     │
│         ▼                ▼                ▼                     │
│    ┌─────────────────────────────────────────────────────────┐ │
│    │              Quorum Consensus (2/3)                     │ │
│    │  • Compare responses                                    │ │
│    │  • Detect disagreements                                 │ │
│    │  • Return majority value                                │ │
│    └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Witness Selection Algorithm

```rust
// src/dht/witness_selection.rs
pub struct WitnessSelector {
    dht: DhtNetworkManager,
    trust: EigenTrustManager,
    geo: GeographicRouter,
}

impl WitnessSelector {
    pub async fn select_witnesses(
        &self,
        key: &Key,
        count: usize,
    ) -> Result<Vec<WitnessNode>> {
        // 1. Get K closest nodes
        let candidates = self.dht.get_closest_peers(key, self.config.k).await;

        // 2. Filter by reputation
        let reputable: Vec<_> = candidates
            .into_iter()
            .filter(|p| self.trust.get_score(&p.id) >= MIN_WITNESS_TRUST)
            .collect();

        // 3. Ensure geographic diversity
        let diverse = self.geo.select_diverse(reputable, count)?;

        // 4. Verify minimum requirements
        if diverse.len() < count {
            return Err(P2PError::InsufficientWitnesses);
        }

        Ok(diverse)
    }
}
```

### Store with Witnesses

```rust
pub async fn store_with_witnesses(
    &self,
    key: Key,
    value: Record,
    ttl: Duration,
) -> Result<StoreReceipt> {
    // Select witnesses
    let witnesses = self.select_witnesses(&key, 3).await?;

    // Sign the value
    let signed_value = self.sign_record(&value)?;

    // Store on all K closest nodes
    let store_futures: Vec<_> = self.closest_nodes(&key)
        .map(|node| self.store_on_node(node, &key, &signed_value))
        .collect();

    let results = futures::future::join_all(store_futures).await;

    // Collect witness attestations
    let attestations = self.collect_attestations(&witnesses, &key, &signed_value).await?;

    // Require quorum of witness signatures
    if attestations.len() < 2 {
        return Err(P2PError::InsufficientWitnessAttestation);
    }

    Ok(StoreReceipt {
        key,
        witnesses: witnesses.into_iter().map(|w| w.id).collect(),
        attestations,
        stored_at: SystemTime::now(),
        ttl,
    })
}
```

### Get with Witness Validation

```rust
pub async fn get_with_validation(&self, key: &Key) -> Result<ValidatedRecord> {
    // Query multiple paths (S/Kademlia disjoint paths)
    let paths = self.generate_disjoint_paths(key, 3);

    let query_futures: Vec<_> = paths
        .into_iter()
        .map(|path| self.query_path(key, path))
        .collect();

    let responses = futures::future::join_all(query_futures).await;

    // Collect all unique values
    let values: HashMap<Hash, (Record, Vec<PeerId>)> = /* group by content hash */;

    // Find majority value
    let (majority_value, supporters) = values
        .into_iter()
        .max_by_key(|(_, (_, peers))| peers.len())
        .ok_or(P2PError::RecordNotFound)?;

    // Verify we have quorum
    if supporters.len() < self.config.quorum_size {
        return Err(P2PError::NoQuorumReached);
    }

    // Verify signatures
    self.verify_record_signatures(&majority_value)?;

    Ok(ValidatedRecord {
        record: majority_value,
        quorum_size: supporters.len(),
        dissenting_peers: /* peers that returned different values */,
    })
}
```

### Byzantine Fault Tolerance

The system tolerates up to `f` Byzantine nodes out of `3f+1` total:

| Configuration | Total Nodes | Max Byzantine | Quorum Size |
|---------------|-------------|---------------|-------------|
| Default       | 4           | 1             | 3           |
| Enhanced      | 7           | 2             | 5           |
| High Security | 10          | 3             | 7           |

### Witness Attestation Format

```rust
pub struct WitnessAttestation {
    /// Witness node identifier
    pub witness_id: PeerId,

    /// Key being attested
    pub key: Key,

    /// Hash of the value
    pub value_hash: [u8; 32],

    /// Timestamp of attestation
    pub timestamp: SystemTime,

    /// Geographic region of witness
    pub region: NetworkRegion,

    /// ML-DSA signature
    pub signature: MlDsaSignature,
}
```

## Consequences

### Positive

1. **Byzantine fault tolerance**: Survives minority of malicious nodes
2. **Data integrity**: Witness attestations prove correct storage
3. **Eclipse resistance**: Geographic diversity prevents regional attacks
4. **Audit trail**: Attestations provide accountability
5. **Sybil mitigation**: Reputation requirements for witnesses

### Negative

1. **Latency**: Multiple round trips for witness queries
2. **Bandwidth**: Additional attestation data
3. **Complexity**: More failure modes to handle
4. **Bootstrap dependency**: New nodes need reputation before witnessing

### Neutral

1. **Storage overhead**: Attestations stored with records
2. **Witness availability**: May need fallback to fewer witnesses

## Consistency Levels

Applications can choose their consistency requirements:

```rust
pub enum ConsistencyLevel {
    /// Best-effort, single response
    Eventual,

    /// Majority agreement (default)
    Quorum,

    /// All nodes must agree
    All,

    /// Custom witness count
    Custom { witnesses: usize, required: usize },
}
```

## Iterative Lookup Safeguards

To keep iterative lookups aligned with the multi-layer architecture, the DHT network manager now enforces:

- **FIFO candidate queues**: new nodes are appended to a bounded queue (Kademlia-style K-buckets) and duplicates are ignored. When the queue hits `MAX_CANDIDATE_NODES` we drop the newest entrants, preserving the oldest, better-observed peers.
- **Stagnation detection**: each iteration snapshots the candidate set; if the next iteration would query the identical peer set, the lookup terminates early instead of looping forever.
- **Trust feedback hooks**: every successful response (value or closer nodes) reports a positive event to EigenTrust, while failures/timeouts register negative events. This keeps the trust layer informed without leaking panic paths.
- **Single-socket parallelism**: all ALPHA-parallel queries share the same saorsa-transport connection pool, so we retain the geo-aware transport guarantees while still querying multiple peers concurrently.

These safeguards ensure the DHT layer respects EigenTrust scoring, geographic awareness (enforced by the transport layer), and the architectural STOP conditions described in ADR-001.

Implementation reference: `DhtNetworkManager::get` and `DhtNetworkManager::find_closest_nodes_network`
(in `src/dht_network_manager.rs`) enforce the queue window, duplicate suppression, stagnation check,
and EigenTrust feedback loop described above.

## Alternatives Considered

### Pure Kademlia

Standard Kademlia without witnesses.

**Rejected because**:
- No Byzantine fault tolerance
- Vulnerable to eclipse attacks
- Cannot detect data corruption

### Blockchain-Based Storage

Use a blockchain for consensus.

**Rejected because**:
- High latency for storage operations
- Scalability limitations
- Energy-intensive (if PoW)

### Trusted Notaries

Designated trusted nodes validate operations.

**Rejected because**:
- Centralization risk
- Single points of failure
- Trust model conflicts with P2P philosophy

### PBFT Consensus

Practical Byzantine Fault Tolerance for each operation.

**Rejected because**:
- O(n²) message complexity
- Doesn't scale to thousands of nodes
- Overkill for DHT operations

## References

- [S/Kademlia: A Practicable Approach Towards Secure Key-Based Routing](https://ieeexplore.ieee.org/document/4447808)
- [Kademlia: A Peer-to-peer Information System Based on the XOR Metric](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf)
- [PBFT: Practical Byzantine Fault Tolerance](https://pmg.csail.mit.edu/papers/osdi99.pdf)
- [Eclipse Attacks on Bitcoin's Peer-to-Peer Network](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-heilman.pdf)
- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
