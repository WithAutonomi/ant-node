# Close Group Stability Findings for Merkle Payments

## BEFORE Fixes — Baseline Test Results

| Test | Network Size | Metric | Result |
|------|-------------|--------|--------|
| Routing Table Completeness | 25 nodes | DHT discovery | **12.2/25 (48.8%)** — but 22.7/25 direct connections |
| Routing Table Completeness | 100 nodes | DHT discovery | **13.3/100 (13.3%)** — critical degradation |
| Ground Truth Overlap | 5 nodes | Close group accuracy | **1.000 (100%)** — perfect |
| Ground Truth Overlap | 25 nodes | Close group accuracy | **0.992 (99.2%)** — excellent |
| Ground Truth Overlap | 100 nodes | Close group accuracy | **0.883 (88.3%)**, min **0.520** |
| Quoting vs Verification | 25 nodes | Client-Verifier Jaccard | **0.983**, 19/20 exact matches |
| Quoting vs Verification | 100 nodes | Client-Verifier Jaccard | **0.801**, only 3/20 exact matches, **1/20 payment failure** |
| Temporal Stability | 25 nodes | Drift over time | **1.000** — no drift (static network) |
| DHT Lookup Size | 25 nodes | Results per query (K=5) | **5.00** — always returns K peers |

## AFTER Fixes — Improved Results

| Test | Network Size | Metric | Before | After | Change |
|------|-------------|--------|--------|-------|--------|
| Routing Table Discovery | 100 nodes | Avg DHT discovery | 13.3/100 | **16.7/100** | +25% |
| Ground Truth Overlap | 100 nodes | Min overlap | 0.520 | **0.660** | +27% |
| Ground Truth Overlap | 100 nodes | Targets with majority | 19/20 | **20/20** | +5% |
| Quoting vs Verification | 25 nodes | Jaccard | 0.983 | **1.000** | Perfect |
| Quoting vs Verification | 25 nodes | Exact matches | 19/20 | **20/20** | Perfect |
| Direct Connections | 25 nodes | Min connections | 18 | **24** | +33% |

## Root Causes Identified

### 1. DHT routing tables are severely underpopulated (PRIMARY ISSUE)

- Nodes are **directly connected** to most peers (22.7/25, 90.8%)
- But the **DHT only discovers 13.3/100 (13.3%)** of the network
- This gap grows with network size — the connection layer sees peers but the DHT routing table doesn't incorporate them
- This is NOT a geo-location issue (geo was disabled via `CoreDiversityConfig::permissive()`)

### 2. Kademlia iterative lookup partially compensates

- Despite only knowing ~13% of nodes, iterative lookups achieve 88% ground truth overlap at 100 nodes
- This is because lookups hop through intermediate nodes that know different subsets
- But it's not enough: **5% of addresses get <60% overlap**, meaning payment verification would fail

### 3. Quoting vs Verification divergence scales with network size

- At 25 nodes: 98.3% Jaccard, 95% exact match rate
- At 100 nodes: **80.1% Jaccard, only 15% exact match rate, 5% payment failure rate**
- Extrapolating to 1000+ nodes: the failure rate would be significantly worse

### 4. Geo-location is NOT the culprit (for this test environment)

- All tests ran with `CoreDiversityConfig::permissive()` — no geo checks
- The problem is in the DHT routing table population itself, not in admission filters

## What This Means for Merkle Payments

At 100 nodes in an ideal localhost environment with no churn, no latency, and no geo-location filtering:

- **5% of payment verification attempts would fail** (client and verifier disagree on close group)
- **Only 15% of lookups produce identical close groups** between quoting and verification
- On a real network with churn, latency, and geo-diversity, the failure rate would be much higher

## Implemented Fixes

### Fix 1: Aggressive DHT routing table refresh (`src/node.rs`, `tests/e2e/testnet.rs`)

Periodic background task that performs random DHT lookups to populate routing tables more aggressively. Instead of only discovering peers during on-demand lookups, nodes proactively explore the address space every 30s (production) or 10s (tests).

**Impact**: Routing table discovery improved from 13.3% to 16.7% at 100 nodes (+25%). At 25 nodes, the quoting-vs-verification test went from 19/20 to **20/20 perfect agreement** (Jaccard 0.983 to 1.000).

### Fix 2: Close group confirmation protocol (`src/close_group.rs`)

New module providing:
- `confirm_close_group()` — queries multiple nodes independently for the closest peers to an address, returns only peers that appear in a threshold number of lookups. This creates consensus on close group membership.
- `is_node_in_close_group()` — checks if a node itself should be part of the close group for an address by comparing its own XOR distance against the DHT results.

### Fix 3: Close group validation in PUT handler (`src/storage/handler.rs`)

`AntProtocol` now optionally holds a reference to the `P2PNode` (via `OnceLock` for deferred initialization). During PUT requests, before payment verification, the handler calls `is_node_in_close_group()` to verify the node is actually responsible for the address. This prevents nodes from storing data they're not close to, which is critical for merkle payment verification.

Wired in production (`src/node.rs`) via `with_p2p_node()` and in tests (`tests/e2e/testnet.rs`) via `set_p2p_node()`.

## Remaining Concerns

1. **100-node networks still show variability** — the DHT refresh helps but routing tables remain at ~17% discovery. The `saorsa-core` DHT may need internal improvements to its routing table maintenance.

2. **The core limitation is in saorsa-core** — ant-node can only work around the DHT's routing table population behavior. The ideal fix would be for `saorsa-core` to automatically populate routing table entries from connected peers.

3. **Real-world conditions will be worse** — these tests use localhost with no latency, no churn, and no geo-filtering. A production network with global distribution and node churn will have higher divergence rates.

4. **Scaling beyond 100 nodes untested** — the pattern suggests the problem worsens as N grows since the probability of the 5 true closest nodes all being in a 17% routing table window decreases.

## Files Changed

| File | Change |
|------|--------|
| `src/node.rs` | DHT refresh background task, P2P node wiring to AntProtocol |
| `src/close_group.rs` | New module: close group confirmation protocol |
| `src/storage/handler.rs` | Close group check in PUT handler, OnceLock P2P node field |
| `src/lib.rs` | Register close_group module |
| `tests/e2e/testnet.rs` | DHT refresh task per test node, P2P node wiring |
| `tests/e2e/close_group_stability.rs` | New: 8 comprehensive test cases |
| `tests/e2e/mod.rs` | Register new test modules |
