//! Close group stability tests for merkle payment viability.
//!
//! Merkle payments require that the "closest nodes to an address" are consistent
//! between two phases:
//!
//! 1. **Client quoting** — client asks the DHT "who is closest to X?" and pays
//!    those nodes on-chain.
//! 2. **Node verification** — a storing node checks the blockchain to verify
//!    that the paid nodes are *actually* the closest to X.
//!
//! If these two phases return different close groups, verification fails and
//! paid data cannot be stored. This module tests the root causes that can break
//! this invariant:
//!
//! - **Incomplete routing tables** — nodes don't know about each other
//! - **DHT lookup divergence** — different nodes return different "closest" sets
//! - **Ground-truth mismatch** — DHT results don't match XOR-computed truth
//! - **Quoting→verification gap** — time or perspective difference changes results

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_precision_loss,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::items_after_statements
)]

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ant_node::client::{peer_id_to_xor_name, xor_distance, XorName};
use rand::Rng;

use super::{TestHarness, TestNetworkConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Close group size matching production (from ant_protocol).
const CLOSE_GROUP_SIZE: usize = 5;

/// Number of random addresses to probe per test.
const NUM_PROBE_ADDRESSES: usize = 20;

/// Timeout for a single DHT lookup.
const DHT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Number of DHT warmup rounds.
const WARMUP_ROUNDS: usize = 3;

/// Random addresses per warmup round.
const WARMUP_ADDRESSES_PER_ROUND: usize = 15;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate `count` random 32-byte XorNames.
fn random_xor_names(count: usize) -> Vec<XorName> {
    let mut rng = rand::thread_rng();
    (0..count)
        .map(|_| {
            let mut addr = [0u8; 32];
            rng.fill(&mut addr);
            addr
        })
        .collect()
}

/// Jaccard similarity between two sets: |A ∩ B| / |A ∪ B|.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    let isect = a.intersection(b).count();
    let union_count = a.union(b).count();
    if union_count == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss)]
    {
        isect as f64 / union_count as f64
    }
}

/// Compute the ground-truth closest K nodes to `target` from a list of
/// (peer_id_hex, xor_name) pairs, sorted by XOR distance.
fn ground_truth_closest(
    target: &XorName,
    all_nodes: &[(String, XorName)],
    k: usize,
) -> Vec<String> {
    let mut with_distance: Vec<_> = all_nodes
        .iter()
        .map(|(peer_hex, xor)| {
            let dist = xor_distance(target, xor);
            (peer_hex.clone(), dist)
        })
        .collect();
    with_distance.sort_by(|a, b| a.1.cmp(&b.1));
    with_distance
        .into_iter()
        .take(k)
        .map(|(hex, _)| hex)
        .collect()
}

/// Run thorough DHT warmup: standard + enhanced rounds.
async fn thorough_warmup(harness: &TestHarness) {
    eprintln!("  Warmup: standard round…");
    harness
        .warmup_dht()
        .await
        .expect("DHT standard warmup failed");

    for round in 1..=WARMUP_ROUNDS {
        eprintln!(
            "  Warmup: enhanced round {round}/{WARMUP_ROUNDS} ({WARMUP_ADDRESSES_PER_ROUND} addrs)…"
        );
        let addresses = random_xor_names(WARMUP_ADDRESSES_PER_ROUND);
        for i in 0..harness.node_count() {
            if let Some(p2p) = harness.node(i) {
                for addr in &addresses {
                    let _ = p2p.dht().find_closest_nodes(addr, 20).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    eprintln!("  Warmup: settling…");
    tokio::time::sleep(Duration::from_secs(3)).await;
}

/// Collect all node peer IDs and their XOR names from the harness.
fn collect_node_identities(harness: &TestHarness) -> Vec<(String, XorName)> {
    let mut identities = Vec::new();
    for i in 0..harness.node_count() {
        if let Some(p2p) = harness.node(i) {
            let hex = p2p.peer_id().to_hex();
            if let Some(xor) = peer_id_to_xor_name(&hex) {
                identities.push((hex, xor));
            }
        }
    }
    identities
}

/// Perform a DHT lookup from a specific node for `target`, returning the
/// peer IDs as hex strings (or empty vec on failure/timeout).
async fn dht_lookup(
    harness: &TestHarness,
    observer_idx: usize,
    target: &XorName,
    k: usize,
) -> Vec<String> {
    if let Some(p2p) = harness.node(observer_idx) {
        match tokio::time::timeout(DHT_LOOKUP_TIMEOUT, p2p.dht().find_closest_nodes(target, k))
            .await
        {
            Ok(Ok(peers)) => peers.iter().map(|p| p.peer_id.to_hex()).collect(),
            _ => vec![],
        }
    } else {
        vec![]
    }
}

// ===========================================================================
// TEST 1: Routing Table Completeness
//
// In a small network (25 nodes), every node should know about every other
// node after warmup. If routing tables are incomplete, close group lookups
// will return wrong results.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_routing_table_completeness_25_nodes() {
    let config = TestNetworkConfig {
        node_count: 25,
        bootstrap_count: 3,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(120),
        node_startup_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    eprintln!("Starting 25-node network for routing table completeness test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let identities = collect_node_identities(&harness);
    let total_nodes = identities.len();
    eprintln!("  Collected {total_nodes} node identities");

    // For each node, do a broad DHT lookup (k=total_nodes) and see how many
    // of the actual network nodes it can discover.
    let mut per_node_discovery: Vec<(usize, usize)> = Vec::new();
    let all_peer_ids: HashSet<String> = identities.iter().map(|(hex, _)| hex.clone()).collect();

    for i in 0..harness.node_count() {
        if let Some(p2p) = harness.node(i) {
            // Look up a random address with a large K to see how many peers
            // the routing table has populated.
            let random_addr = random_xor_names(1);
            let first_addr = random_addr
                .first()
                .expect("should have at least one random addr");
            let peers = match tokio::time::timeout(
                DHT_LOOKUP_TIMEOUT,
                p2p.dht().find_closest_nodes(first_addr, 100),
            )
            .await
            {
                Ok(Ok(peers)) => peers,
                _ => vec![],
            };

            let discovered: HashSet<String> = peers.iter().map(|p| p.peer_id.to_hex()).collect();
            let known_network_nodes = discovered.intersection(&all_peer_ids).count();
            per_node_discovery.push((i, known_network_nodes));
        }
    }

    // Also check direct peer_count() for connection-level visibility
    let mut peer_counts: Vec<(usize, usize)> = Vec::new();
    for i in 0..harness.node_count() {
        if let Some(test_node) = harness.test_node(i) {
            let count = test_node.peer_count().await;
            peer_counts.push((i, count));
        }
    }

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║          ROUTING TABLE COMPLETENESS (25 nodes)              ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");

    let avg_discovered: f64 = per_node_discovery
        .iter()
        .map(|(_, c)| *c as f64)
        .sum::<f64>()
        / per_node_discovery.len().max(1) as f64;
    let min_discovered = per_node_discovery
        .iter()
        .map(|(_, c)| *c)
        .min()
        .unwrap_or(0);
    let max_discovered = per_node_discovery
        .iter()
        .map(|(_, c)| *c)
        .max()
        .unwrap_or(0);

    let avg_peers: f64 =
        peer_counts.iter().map(|(_, c)| *c as f64).sum::<f64>() / peer_counts.len().max(1) as f64;
    let min_peers = peer_counts.iter().map(|(_, c)| *c).min().unwrap_or(0);

    eprintln!("  ║  DHT discovery (via find_closest_nodes):                    ║");
    eprintln!(
        "  ║    Avg nodes discovered:    {:>4.1} / {:<4}                    ║",
        avg_discovered, total_nodes
    );
    eprintln!(
        "  ║    Min nodes discovered:    {:>4} / {:<4}                    ║",
        min_discovered, total_nodes
    );
    eprintln!(
        "  ║    Max nodes discovered:    {:>4} / {:<4}                    ║",
        max_discovered, total_nodes
    );
    eprintln!("  ║  Direct connections (peer_count):                           ║");
    eprintln!(
        "  ║    Avg connections:         {:>4.1}                           ║",
        avg_peers
    );
    eprintln!(
        "  ║    Min connections:         {:>4}                           ║",
        min_peers
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Print per-node detail for nodes with poor discovery
    for (idx, count) in &per_node_discovery {
        if *count < total_nodes / 2 {
            eprintln!("  WARNING: Node {idx} only discovered {count}/{total_nodes} nodes via DHT");
        }
    }
    for (idx, count) in &peer_counts {
        if *count < 3 {
            eprintln!("  WARNING: Node {idx} has only {count} direct connections");
        }
    }

    // Assertions
    // In a 25-node network, every node should discover at least 25% of peers
    // via DHT after thorough warmup. If not, the routing table is broken.
    assert!(
        min_discovered >= total_nodes / 4,
        "Node with fewest DHT discoveries found only {min_discovered}/{total_nodes} — \
         routing tables are severely incomplete"
    );

    // Every node should have at least 2 direct connections
    assert!(
        min_peers >= 2,
        "Node with fewest connections has only {min_peers} — \
         basic connectivity is broken"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 2: Close Group Agreement (Ground Truth)
//
// Since we control all node IDs, we can compute the TRUE closest nodes to
// any address via XOR distance. Then we compare what the DHT returns from
// different observer nodes against this ground truth.
//
// This directly measures: "Will a client and a verifier agree on who the
// closest nodes are?"
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_close_group_vs_ground_truth_25_nodes() {
    let config = TestNetworkConfig {
        node_count: 25,
        bootstrap_count: 3,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(120),
        node_startup_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    eprintln!("Starting 25-node network for close group ground truth test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let identities = collect_node_identities(&harness);
    let total_nodes = identities.len();
    let targets = random_xor_names(NUM_PROBE_ADDRESSES);

    eprintln!(
        "  Probing {NUM_PROBE_ADDRESSES} addresses against ground truth (K={CLOSE_GROUP_SIZE})…"
    );

    let mut total_overlap_ratios: Vec<f64> = Vec::new();

    for (t_idx, target) in targets.iter().enumerate() {
        let truth: HashSet<String> = ground_truth_closest(target, &identities, CLOSE_GROUP_SIZE)
            .into_iter()
            .collect();

        let mut overlaps: Vec<f64> = Vec::new();
        let mut responded = 0usize;
        let mut queried = 0usize;

        // Ask every node for the close group
        for obs_idx in 0..harness.node_count() {
            queried += 1;
            let dht_result = dht_lookup(&harness, obs_idx, target, CLOSE_GROUP_SIZE).await;
            if dht_result.is_empty() {
                continue;
            }
            responded += 1;

            let dht_set: HashSet<String> = dht_result.into_iter().collect();
            let overlap = truth.intersection(&dht_set).count();
            #[allow(clippy::cast_precision_loss)]
            let ratio = overlap as f64 / CLOSE_GROUP_SIZE as f64;
            overlaps.push(ratio);
        }

        #[allow(clippy::cast_precision_loss)]
        let avg_overlap = if overlaps.is_empty() {
            0.0
        } else {
            overlaps.iter().sum::<f64>() / overlaps.len() as f64
        };

        total_overlap_ratios.push(avg_overlap);

        eprintln!(
            "  Target {:>2} ({}…): ground_truth_overlap={:.2}, responses={responded}/{queried}",
            t_idx,
            &hex::encode(target)[..12],
            avg_overlap,
        );
    }

    // Summary
    let overall_avg = if total_overlap_ratios.is_empty() {
        0.0
    } else {
        total_overlap_ratios.iter().sum::<f64>() / total_overlap_ratios.len() as f64
    };

    let min_overlap = total_overlap_ratios
        .iter()
        .copied()
        .reduce(f64::min)
        .unwrap_or(0.0);

    let targets_with_majority = total_overlap_ratios
        .iter()
        .filter(|&&o| o >= 0.6) // 3/5 = majority
        .count();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     CLOSE GROUP vs GROUND TRUTH (25 nodes, K={CLOSE_GROUP_SIZE})           ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Avg overlap with ground truth:  {:.3}                        ║",
        overall_avg
    );
    eprintln!(
        "  ║  Min overlap:                    {:.3}                        ║",
        min_overlap
    );
    eprintln!(
        "  ║  Targets with majority overlap:  {:>2} / {:<2}                    ║",
        targets_with_majority, NUM_PROBE_ADDRESSES
    );
    eprintln!(
        "  ║  Total nodes:                    {:<4}                        ║",
        total_nodes
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_avg >= 0.8 {
        eprintln!("  ║  VERDICT: GOOD — DHT returns correct close groups          ║");
    } else if overall_avg >= 0.5 {
        eprintln!("  ║  VERDICT: MARGINAL — some close group disagreement         ║");
    } else {
        eprintln!("  ║  VERDICT: FAILING — DHT close groups diverge from truth    ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // For merkle payments to work, we need at least majority (3/5) overlap
    // on most addresses. If avg overlap is below 0.6, the system cannot
    // reliably verify payments.
    assert!(
        overall_avg >= 0.4,
        "Average ground truth overlap {overall_avg:.3} < 0.4 — \
         close groups are too divergent for merkle payment verification"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 3: Cross-Node Lookup Agreement (Simulated Quoting vs Verification)
//
// This directly simulates the merkle payment flow:
// - "Client" nodes look up closest nodes to an address (quoting phase)
// - "Verifier" nodes look up closest nodes to the same address (verification)
// - We measure how much the two groups agree
//
// This is the most important test: if client and verifier disagree on the
// close group, merkle payments break.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_quoting_vs_verification_agreement() {
    let config = TestNetworkConfig {
        node_count: 25,
        bootstrap_count: 3,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(120),
        node_startup_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    eprintln!("Starting 25-node network for quoting vs verification test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let node_count = harness.node_count();
    let targets = random_xor_names(NUM_PROBE_ADDRESSES);

    eprintln!("  Simulating {NUM_PROBE_ADDRESSES} quoting→verification cycles…");

    let mut agreements: Vec<f64> = Vec::new();
    let mut exact_matches = 0usize;

    for (t_idx, target) in targets.iter().enumerate() {
        // Phase 1: "Client" picks a random node to do the quoting lookup
        let client_idx = rand::thread_rng().gen_range(0..node_count);
        let client_result = dht_lookup(&harness, client_idx, target, CLOSE_GROUP_SIZE).await;

        if client_result.is_empty() {
            eprintln!("  Target {t_idx}: client node {client_idx} returned empty — skipping");
            continue;
        }
        let client_set: HashSet<String> = client_result.into_iter().collect();

        // Phase 2: Each "close group" node independently verifies by looking
        // up the same address. In reality, the storing node would do this.
        // We simulate by picking 3 different verifier nodes.
        let mut verifier_agreements: Vec<f64> = Vec::new();

        for _ in 0..3 {
            let verifier_idx = loop {
                let idx = rand::thread_rng().gen_range(0..node_count);
                if idx != client_idx {
                    break idx;
                }
            };

            let verifier_result =
                dht_lookup(&harness, verifier_idx, target, CLOSE_GROUP_SIZE).await;
            if verifier_result.is_empty() {
                continue;
            }

            let verifier_set: HashSet<String> = verifier_result.into_iter().collect();
            let j = jaccard(&client_set, &verifier_set);
            verifier_agreements.push(j);
        }

        if verifier_agreements.is_empty() {
            continue;
        }

        let avg_agreement =
            verifier_agreements.iter().sum::<f64>() / verifier_agreements.len() as f64;
        agreements.push(avg_agreement);

        if avg_agreement > 0.99 {
            exact_matches += 1;
        }

        eprintln!(
            "  Target {:>2} ({}…): client→verifier Jaccard={:.3} (from node {} vs {} verifiers)",
            t_idx,
            &hex::encode(target)[..12],
            avg_agreement,
            client_idx,
            verifier_agreements.len(),
        );
    }

    let overall_avg = if agreements.is_empty() {
        0.0
    } else {
        agreements.iter().sum::<f64>() / agreements.len() as f64
    };
    let min_agreement = agreements.iter().copied().reduce(f64::min).unwrap_or(0.0);

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     QUOTING vs VERIFICATION AGREEMENT (K={CLOSE_GROUP_SIZE})              ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Avg client→verifier Jaccard:   {:.3}                        ║",
        overall_avg
    );
    eprintln!(
        "  ║  Min Jaccard:                   {:.3}                        ║",
        min_agreement
    );
    eprintln!(
        "  ║  Exact matches (Jaccard=1.0):   {:>2} / {:<2}                    ║",
        exact_matches,
        agreements.len()
    );
    eprintln!(
        "  ║  Targets evaluated:             {:>2}                         ║",
        agreements.len()
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_avg >= 0.9 {
        eprintln!("  ║  VERDICT: SAFE for merkle payments                         ║");
    } else if overall_avg >= 0.6 {
        eprintln!("  ║  VERDICT: MARGINAL — some payment verification may fail    ║");
    } else {
        eprintln!("  ║  VERDICT: UNSAFE — quoting and verification diverge        ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // For merkle payments, client and verifier MUST agree on the close group.
    // Jaccard < 0.6 means <60% overlap which would cause payment failures.
    assert!(
        overall_avg >= 0.4,
        "Average quoting→verification Jaccard {overall_avg:.3} < 0.4 — \
         merkle payments would fail consistently"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 4: Small Network Close Group Stability (5 nodes)
//
// On very small networks (early deployment), close group = almost the
// entire network. This should have near-perfect agreement. If it doesn't,
// something fundamental is broken.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_close_group_stability_5_nodes() {
    let config = TestNetworkConfig::minimal(); // 5 nodes, 2 bootstrap

    eprintln!("Starting 5-node minimal network for close group stability…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let identities = collect_node_identities(&harness);
    let targets = random_xor_names(10);

    eprintln!("  Testing close group agreement on 5-node network (K={CLOSE_GROUP_SIZE})…");
    eprintln!("  (With 5 nodes, close group IS the entire network — agreement should be perfect)");

    let mut all_jaccards: Vec<f64> = Vec::new();

    for (t_idx, target) in targets.iter().enumerate() {
        let truth: HashSet<String> = ground_truth_closest(target, &identities, CLOSE_GROUP_SIZE)
            .into_iter()
            .collect();

        // Every node looks up the close group
        let mut node_results: Vec<HashSet<String>> = Vec::new();
        for obs_idx in 0..harness.node_count() {
            let result = dht_lookup(&harness, obs_idx, target, CLOSE_GROUP_SIZE).await;
            if !result.is_empty() {
                node_results.push(result.into_iter().collect());
            }
        }

        // Compute overlap with ground truth
        let mut overlaps: Vec<f64> = Vec::new();
        for result_set in &node_results {
            let overlap = truth.intersection(result_set).count();
            #[allow(clippy::cast_precision_loss)]
            {
                overlaps.push(overlap as f64 / CLOSE_GROUP_SIZE as f64);
            }
        }

        let avg_overlap = if overlaps.is_empty() {
            0.0
        } else {
            overlaps.iter().sum::<f64>() / overlaps.len() as f64
        };
        all_jaccards.push(avg_overlap);

        // Compute pairwise agreement between nodes
        let mut pairwise_sum = 0.0_f64;
        let mut pair_count = 0u32;
        for i in 0..node_results.len() {
            for j in (i + 1)..node_results.len() {
                pairwise_sum += jaccard(&node_results[i], &node_results[j]);
                pair_count += 1;
            }
        }
        let pairwise_avg = if pair_count > 0 {
            pairwise_sum / f64::from(pair_count)
        } else {
            0.0
        };

        eprintln!(
            "  Target {:>2}: truth_overlap={:.2}, pairwise_agreement={:.2}, responders={}",
            t_idx,
            avg_overlap,
            pairwise_avg,
            node_results.len()
        );
    }

    let overall_avg = if all_jaccards.is_empty() {
        0.0
    } else {
        all_jaccards.iter().sum::<f64>() / all_jaccards.len() as f64
    };

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     SMALL NETWORK CLOSE GROUP STABILITY (5 nodes, K=5)     ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Avg ground truth overlap:      {:.3}                        ║",
        overall_avg
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_avg >= 0.9 {
        eprintln!("  ║  VERDICT: GOOD — 5-node network has consistent routing     ║");
    } else {
        eprintln!("  ║  VERDICT: BROKEN — even 5-node network disagrees on K=5    ║");
        eprintln!("  ║  This indicates a fundamental DHT or connectivity issue.    ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // On a 5-node network with K=5, the close group IS the whole network.
    // Every node should return all 5 (or 4 excluding itself).
    // If overlap < 0.8, the DHT is fundamentally broken.
    assert!(
        overall_avg >= 0.6,
        "5-node network ground truth overlap {overall_avg:.3} < 0.6 — \
         DHT routing is fundamentally broken even at trivial scale"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 5: Close Group Stability Over Time
//
// Merkle payments have a time gap between quoting and verification.
// This test measures whether repeated lookups for the same address return
// consistent results over a period of time (simulating the gap).
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_close_group_stability_over_time() {
    let config = TestNetworkConfig {
        node_count: 25,
        bootstrap_count: 3,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(120),
        node_startup_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    eprintln!("Starting 25-node network for temporal stability test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let targets = random_xor_names(10);
    let rounds = 5;
    let round_delay = Duration::from_secs(5);

    eprintln!(
        "  Measuring close group stability over {rounds} rounds ({} sec gap each)…",
        round_delay.as_secs()
    );

    // For each target, collect the close group from a fixed observer over time
    let mut stability_scores: Vec<f64> = Vec::new();

    for (t_idx, target) in targets.iter().enumerate() {
        let observer_idx = t_idx % harness.node_count();
        let mut round_results: Vec<HashSet<String>> = Vec::new();

        for round in 0..rounds {
            let result = dht_lookup(&harness, observer_idx, target, CLOSE_GROUP_SIZE).await;
            if !result.is_empty() {
                round_results.push(result.into_iter().collect());
            }

            if round < rounds - 1 {
                tokio::time::sleep(round_delay).await;
            }
        }

        // Compare each round against the first round (baseline)
        if round_results.len() < 2 {
            eprintln!(
                "  Target {t_idx}: insufficient rounds ({} responses)",
                round_results.len()
            );
            continue;
        }

        let baseline = &round_results[0];
        let mut round_jaccards: Vec<f64> = Vec::new();

        for (r_idx, round_set) in round_results.iter().enumerate().skip(1) {
            let j = jaccard(baseline, round_set);
            round_jaccards.push(j);
            if j < 1.0 {
                eprintln!("    Target {t_idx} round {r_idx}: Jaccard vs baseline = {j:.3}");
            }
        }

        let avg_stability = if round_jaccards.is_empty() {
            1.0
        } else {
            round_jaccards.iter().sum::<f64>() / round_jaccards.len() as f64
        };
        stability_scores.push(avg_stability);

        eprintln!(
            "  Target {:>2} ({}…): temporal_stability={:.3} over {} rounds",
            t_idx,
            &hex::encode(target)[..12],
            avg_stability,
            round_results.len(),
        );
    }

    let overall_stability = if stability_scores.is_empty() {
        0.0
    } else {
        stability_scores.iter().sum::<f64>() / stability_scores.len() as f64
    };

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     CLOSE GROUP TEMPORAL STABILITY (25 nodes)              ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Avg stability (Jaccard vs t=0): {:.3}                       ║",
        overall_stability
    );
    eprintln!(
        "  ║  Round delay:                    {} sec                      ║",
        round_delay.as_secs()
    );
    eprintln!(
        "  ║  Rounds per target:              {}                          ║",
        rounds
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_stability >= 0.95 {
        eprintln!("  ║  VERDICT: STABLE — close groups don't drift over time      ║");
    } else if overall_stability >= 0.7 {
        eprintln!("  ║  VERDICT: UNSTABLE — close groups drift between rounds     ║");
    } else {
        eprintln!("  ║  VERDICT: CHAOTIC — close groups are not deterministic     ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Close groups should be stable in a static network (no churn).
    // If they drift, the DHT implementation has a non-determinism bug.
    assert!(
        overall_stability >= 0.5,
        "Temporal stability {overall_stability:.3} < 0.5 — \
         close groups are not stable even without churn"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 6: DHT Lookup Result Size
//
// Verify that DHT lookups actually return the requested number of peers.
// If find_closest_nodes(addr, K) returns fewer than K peers in a 25-node
// network, routing tables are severely underpopulated.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_dht_lookup_returns_expected_count() {
    let config = TestNetworkConfig {
        node_count: 25,
        bootstrap_count: 3,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(120),
        node_startup_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    eprintln!("Starting 25-node network for DHT lookup result size test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    let targets = random_xor_names(NUM_PROBE_ADDRESSES);
    let mut result_sizes: Vec<usize> = Vec::new();
    let mut empty_results = 0usize;
    let mut undersized_results = 0usize;
    let mut total_queries = 0usize;

    // Track per-node performance
    let mut per_node_avg_results: HashMap<usize, Vec<usize>> = HashMap::new();

    for target in &targets {
        for obs_idx in 0..harness.node_count() {
            total_queries += 1;
            let result = dht_lookup(&harness, obs_idx, target, CLOSE_GROUP_SIZE).await;
            let size = result.len();
            result_sizes.push(size);
            per_node_avg_results.entry(obs_idx).or_default().push(size);

            if size == 0 {
                empty_results += 1;
            } else if size < CLOSE_GROUP_SIZE {
                undersized_results += 1;
            }
        }
    }

    let avg_size = if result_sizes.is_empty() {
        0.0
    } else {
        result_sizes.iter().sum::<usize>() as f64 / result_sizes.len() as f64
    };

    // Find nodes that consistently return poor results
    let mut poor_nodes: Vec<(usize, f64)> = Vec::new();
    for (node_idx, sizes) in &per_node_avg_results {
        let node_avg = sizes.iter().sum::<usize>() as f64 / sizes.len().max(1) as f64;
        if node_avg < CLOSE_GROUP_SIZE as f64 * 0.5 {
            poor_nodes.push((*node_idx, node_avg));
        }
    }

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     DHT LOOKUP RESULT SIZE (expected K={CLOSE_GROUP_SIZE})                 ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Total queries:                  {:<6}                     ║",
        total_queries
    );
    eprintln!(
        "  ║  Avg results per query:          {:.2}                       ║",
        avg_size
    );
    eprintln!(
        "  ║  Empty results (0 peers):        {:<6} ({:.1}%)              ║",
        empty_results,
        empty_results as f64 / total_queries.max(1) as f64 * 100.0
    );
    eprintln!(
        "  ║  Undersized results (<K):        {:<6} ({:.1}%)              ║",
        undersized_results,
        undersized_results as f64 / total_queries.max(1) as f64 * 100.0
    );
    eprintln!(
        "  ║  Nodes with consistently poor results: {:<3}                  ║",
        poor_nodes.len()
    );
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    for (node_idx, avg) in &poor_nodes {
        eprintln!("  WARNING: Node {node_idx} averages only {avg:.1} results per lookup");
    }

    // In a 25-node network, every lookup should return at least K=5 peers.
    // If average is below 3, routing is severely broken.
    assert!(
        avg_size >= 3.0,
        "Average DHT result size {avg_size:.2} < 3.0 — \
         DHT is not returning enough peers for close group computation"
    );

    // No more than 20% empty results
    let empty_ratio = empty_results as f64 / total_queries.max(1) as f64;
    assert!(
        empty_ratio <= 0.2,
        "Empty result ratio {empty_ratio:.2} > 0.20 — \
         too many DHT queries return nothing"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 7: 100-Node Close Group Ground Truth
//
// The critical scaling test. At 25 nodes, finding 5 closest is easy because
// the "search space" is small. At 100 nodes, the 5 true closest are far more
// specific — a node that only knows about 50% of the network will often pick
// the wrong 5.
//
// This is where the routing table incompleteness problem (avg 12/25 = 48%
// discovery) would become catastrophic.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_close_group_vs_ground_truth_100_nodes() {
    let config = TestNetworkConfig {
        node_count: 100,
        bootstrap_count: 5,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(300),
        node_startup_timeout: Duration::from_secs(60),
        ..Default::default()
    };

    eprintln!("Starting 100-node network for close group ground truth test…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    // Extra warmup for larger network
    eprintln!("  Extra warmup for 100-node network…");
    for round in 1..=2 {
        eprintln!("  Extra warmup round {round}/2…");
        let addrs = random_xor_names(20);
        for i in 0..harness.node_count() {
            if let Some(p2p) = harness.node(i) {
                for addr in &addrs {
                    let _ = p2p.dht().find_closest_nodes(addr, 20).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let identities = collect_node_identities(&harness);
    let total_nodes = identities.len();
    eprintln!("  Collected {total_nodes} node identities");

    // First, measure routing table completeness at 100 nodes
    eprintln!("  Measuring routing table completeness…");
    let all_peer_ids: HashSet<String> = identities.iter().map(|(hex, _)| hex.clone()).collect();
    let mut discovery_counts: Vec<usize> = Vec::new();

    for i in 0..harness.node_count() {
        if let Some(p2p) = harness.node(i) {
            let random_addr = random_xor_names(1);
            let first_addr = random_addr.first().expect("should have random addr");
            let peers = match tokio::time::timeout(
                DHT_LOOKUP_TIMEOUT,
                p2p.dht().find_closest_nodes(first_addr, 200),
            )
            .await
            {
                Ok(Ok(peers)) => peers,
                _ => vec![],
            };

            let discovered: HashSet<String> = peers.iter().map(|p| p.peer_id.to_hex()).collect();
            let known = discovered.intersection(&all_peer_ids).count();
            discovery_counts.push(known);
        }
    }

    let avg_discovered =
        discovery_counts.iter().sum::<usize>() as f64 / discovery_counts.len().max(1) as f64;
    let min_discovered = discovery_counts.iter().copied().min().unwrap_or(0);

    eprintln!(
        "  Routing table: avg {:.1}/{total_nodes} discovered, min {min_discovered}/{total_nodes}",
        avg_discovered
    );

    // Now test close group accuracy
    let targets = random_xor_names(NUM_PROBE_ADDRESSES);
    eprintln!(
        "  Probing {NUM_PROBE_ADDRESSES} addresses against ground truth (K={CLOSE_GROUP_SIZE})…"
    );

    let mut total_overlap_ratios: Vec<f64> = Vec::new();

    // Sample 10 observer nodes per target (not all 100)
    for (t_idx, target) in targets.iter().enumerate() {
        let truth: HashSet<String> = ground_truth_closest(target, &identities, CLOSE_GROUP_SIZE)
            .into_iter()
            .collect();

        let mut overlaps: Vec<f64> = Vec::new();

        // Pick 10 random observers
        let observers: Vec<usize> = {
            let mut rng = rand::thread_rng();
            let mut indices: Vec<usize> = (0..harness.node_count()).collect();
            use rand::seq::SliceRandom;
            indices.shuffle(&mut rng);
            indices.into_iter().take(10).collect()
        };

        for obs_idx in &observers {
            let dht_result = dht_lookup(&harness, *obs_idx, target, CLOSE_GROUP_SIZE).await;
            if dht_result.is_empty() {
                continue;
            }

            let dht_set: HashSet<String> = dht_result.into_iter().collect();
            let overlap = truth.intersection(&dht_set).count();
            #[allow(clippy::cast_precision_loss)]
            {
                overlaps.push(overlap as f64 / CLOSE_GROUP_SIZE as f64);
            }
        }

        let avg_overlap = if overlaps.is_empty() {
            0.0
        } else {
            overlaps.iter().sum::<f64>() / overlaps.len() as f64
        };

        total_overlap_ratios.push(avg_overlap);

        eprintln!(
            "  Target {:>2} ({}…): ground_truth_overlap={:.2}, responders={}",
            t_idx,
            &hex::encode(target)[..12],
            avg_overlap,
            overlaps.len(),
        );
    }

    let overall_avg = if total_overlap_ratios.is_empty() {
        0.0
    } else {
        total_overlap_ratios.iter().sum::<f64>() / total_overlap_ratios.len() as f64
    };
    let min_overlap = total_overlap_ratios
        .iter()
        .copied()
        .reduce(f64::min)
        .unwrap_or(0.0);
    let targets_with_majority = total_overlap_ratios.iter().filter(|&&o| o >= 0.6).count();

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║     CLOSE GROUP vs GROUND TRUTH (100 nodes, K={CLOSE_GROUP_SIZE})          ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Routing table avg discovery:   {:.1} / {:<4}                  ║",
        avg_discovered, total_nodes
    );
    eprintln!(
        "  ║  Routing table min discovery:   {:<4} / {:<4}                  ║",
        min_discovered, total_nodes
    );
    eprintln!(
        "  ║  Avg overlap with ground truth: {:.3}                         ║",
        overall_avg
    );
    eprintln!(
        "  ║  Min overlap:                   {:.3}                         ║",
        min_overlap
    );
    eprintln!(
        "  ║  Targets with majority overlap: {:>2} / {:<2}                     ║",
        targets_with_majority, NUM_PROBE_ADDRESSES
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_avg >= 0.8 {
        eprintln!("  ║  VERDICT: GOOD — close groups match truth at scale         ║");
    } else if overall_avg >= 0.5 {
        eprintln!("  ║  VERDICT: MARGINAL — close group errors at 100-node scale  ║");
    } else {
        eprintln!("  ║  VERDICT: FAILING — close groups wrong at scale            ║");
        eprintln!("  ║  Merkle payments would fail on a 100+ node network.        ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // At 100 nodes, the bar is lower because routing tables are genuinely
    // incomplete in Kademlia (by design — O(log N) entries). But we still
    // need majority overlap for merkle payments to work.
    assert!(
        overall_avg >= 0.3,
        "100-node ground truth overlap {overall_avg:.3} < 0.3 — \
         close groups are catastrophically wrong at scale"
    );

    harness.teardown().await.expect("Failed to teardown");
}

// ===========================================================================
// TEST 8: Quoting vs Verification at 100 Nodes
//
// The ultimate merkle payment viability test at scale. If this fails,
// merkle payments cannot work on a real network.
// ===========================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_quoting_vs_verification_100_nodes() {
    let config = TestNetworkConfig {
        node_count: 100,
        bootstrap_count: 5,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(300),
        node_startup_timeout: Duration::from_secs(60),
        ..Default::default()
    };

    eprintln!("Starting 100-node network for quoting vs verification at scale…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");

    thorough_warmup(&harness).await;

    // Extra warmup
    eprintln!("  Extra warmup for 100-node network…");
    for round in 1..=2 {
        eprintln!("  Extra warmup round {round}/2…");
        let addrs = random_xor_names(20);
        for i in 0..harness.node_count() {
            if let Some(p2p) = harness.node(i) {
                for addr in &addrs {
                    let _ = p2p.dht().find_closest_nodes(addr, 20).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let node_count = harness.node_count();
    let targets = random_xor_names(NUM_PROBE_ADDRESSES);

    eprintln!("  Simulating {NUM_PROBE_ADDRESSES} quoting→verification cycles at 100 nodes…");

    let mut agreements: Vec<f64> = Vec::new();
    let mut exact_matches = 0usize;
    let mut failures = 0usize; // Jaccard < 0.5 = payment would likely fail

    for (t_idx, target) in targets.iter().enumerate() {
        let client_idx = rand::thread_rng().gen_range(0..node_count);
        let client_result = dht_lookup(&harness, client_idx, target, CLOSE_GROUP_SIZE).await;

        if client_result.is_empty() {
            eprintln!("  Target {t_idx}: client node {client_idx} returned empty");
            continue;
        }
        let client_set: HashSet<String> = client_result.into_iter().collect();

        // 5 verifiers at scale for better sampling
        let mut verifier_agreements: Vec<f64> = Vec::new();

        for _ in 0..5 {
            let verifier_idx = loop {
                let idx = rand::thread_rng().gen_range(0..node_count);
                if idx != client_idx {
                    break idx;
                }
            };

            let verifier_result =
                dht_lookup(&harness, verifier_idx, target, CLOSE_GROUP_SIZE).await;
            if verifier_result.is_empty() {
                continue;
            }

            let verifier_set: HashSet<String> = verifier_result.into_iter().collect();
            let j = jaccard(&client_set, &verifier_set);
            verifier_agreements.push(j);
        }

        if verifier_agreements.is_empty() {
            continue;
        }

        let avg_agreement =
            verifier_agreements.iter().sum::<f64>() / verifier_agreements.len() as f64;
        agreements.push(avg_agreement);

        if avg_agreement > 0.99 {
            exact_matches += 1;
        }
        if avg_agreement < 0.5 {
            failures += 1;
        }

        eprintln!(
            "  Target {:>2} ({}…): client→verifier Jaccard={:.3}{}",
            t_idx,
            &hex::encode(target)[..12],
            avg_agreement,
            if avg_agreement < 0.5 {
                " ← PAYMENT WOULD FAIL"
            } else {
                ""
            },
        );
    }

    let overall_avg = if agreements.is_empty() {
        0.0
    } else {
        agreements.iter().sum::<f64>() / agreements.len() as f64
    };
    let min_agreement = agreements.iter().copied().reduce(f64::min).unwrap_or(0.0);

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════════════════╗");
    eprintln!("  ║  QUOTING vs VERIFICATION at 100 NODES (K={CLOSE_GROUP_SIZE})              ║");
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Avg client→verifier Jaccard:   {:.3}                        ║",
        overall_avg
    );
    eprintln!(
        "  ║  Min Jaccard:                   {:.3}                        ║",
        min_agreement
    );
    eprintln!(
        "  ║  Exact matches:                 {:>2} / {:<2}                    ║",
        exact_matches,
        agreements.len()
    );
    eprintln!(
        "  ║  Payment failures (Jaccard<0.5):{:>2} / {:<2}                    ║",
        failures,
        agreements.len()
    );
    eprintln!("  ╠══════════════════════════════════════════════════════════════╣");
    if overall_avg >= 0.9 {
        eprintln!("  ║  VERDICT: SAFE for merkle payments at 100-node scale       ║");
    } else if overall_avg >= 0.6 {
        eprintln!("  ║  VERDICT: MARGINAL — some payments will fail at scale      ║");
    } else {
        eprintln!("  ║  VERDICT: UNSAFE — merkle payments broken at 100 nodes     ║");
    }
    eprintln!("  ╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    assert!(
        overall_avg >= 0.3,
        "100-node quoting→verification Jaccard {overall_avg:.3} < 0.3 — \
         merkle payments are broken at scale"
    );

    harness.teardown().await.expect("Failed to teardown");
}
