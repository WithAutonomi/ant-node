//! Network convergence test for 100-node testnet.
//!
//! Uses **lookup path convergence** — the standard metric from DHT measurement
//! literature (Wang & Kangasharju, IEEE P2P 2013; Steiner et al., 2008; IPFS
//! Testground). The idea: if multiple nodes independently perform a full
//! iterative Kademlia lookup for the same key, they should converge to similar
//! result sets. Low pairwise overlap indicates a partitioned / split-view
//! network.
//!
//! This approach requires **zero global knowledge** and scales to any N because:
//! - Each lookup is O(log N) hops (proper iterative Kademlia)
//! - Sample size for statistical confidence is independent of N
//! - We compare observers against *each other*, not against an omniscient oracle

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::time::Duration;

use ant_node::client::XorName;
use rand::seq::SliceRandom;
use rand::Rng;

use super::{TestHarness, TestNetworkConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NODE_COUNT: usize = 100;
const BOOTSTRAP_COUNT: usize = 5;

/// Number of closest peers each DHT lookup requests.
const K: usize = 20;

/// Number of random target keys to probe.
const NUM_TARGETS: usize = 25;

/// Number of observer nodes that independently look up each target.
const NUM_OBSERVERS: usize = 10;

/// Random addresses per enhanced warmup round.
const WARMUP_RANDOM_ADDRESSES: usize = 15;

/// Enhanced warmup rounds.
const WARMUP_ROUNDS: usize = 3;

/// Minimum peers a node must find via DHT for the reachability check.
const MIN_REACHABLE_PEERS: usize = 5;

/// Minimum average pairwise Jaccard similarity across all targets.
/// This measures whether different observers' iterative lookups converge to
/// similar results. Wang & Kangasharju (2013) measured ~0.85 in the
/// 10M-node `BitTorrent` DHT. We use a lower bar for 100 localhost nodes.
const MIN_AVG_PAIRWISE_JACCARD: f64 = 0.25;

/// Minimum fraction of observers that must return non-empty results per target.
const MIN_RESPONSE_RATE: f64 = 0.70;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate `count` random 32-byte addresses.
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

/// Jaccard similarity: |A ∩ B| / |A ∪ B|.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    let isect = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let result = isect as f64 / union as f64;
    result
}

/// Metrics for a single target key probe.
struct TargetProbe {
    avg_pairwise_jaccard: f64,
    response_rate: f64,
    nonempty_sets: usize,
}

/// Probe a single target key from multiple observers and compute the
/// average pairwise Jaccard similarity between their result sets.
async fn probe_target(harness: &TestHarness, target: &XorName, observers: &[usize]) -> TargetProbe {
    let mut result_sets: Vec<HashSet<String>> = Vec::new();
    let mut total_queried = 0usize;

    for &obs_idx in observers {
        if let Some(p2p) = harness.node(obs_idx) {
            total_queried += 1;
            let timeout_dur = Duration::from_secs(30);
            let query = p2p.dht().find_closest_nodes(target, K);
            match tokio::time::timeout(timeout_dur, query).await {
                Ok(Ok(peers)) if !peers.is_empty() => {
                    let set: HashSet<String> = peers.iter().map(|p| p.peer_id.to_hex()).collect();
                    result_sets.push(set);
                }
                _ => {}
            }
        }
    }

    let nonempty_sets = result_sets.len();
    #[allow(clippy::cast_precision_loss)]
    let response_rate = if total_queried == 0 {
        0.0
    } else {
        nonempty_sets as f64 / total_queried as f64
    };

    if nonempty_sets < 2 {
        return TargetProbe {
            avg_pairwise_jaccard: 0.0,
            response_rate,
            nonempty_sets,
        };
    }

    // Compute average pairwise Jaccard across all observer pairs.
    let mut pair_count = 0u32;
    let mut sum_jaccard = 0.0_f64;

    for i in 0..result_sets.len() {
        for j in (i + 1)..result_sets.len() {
            sum_jaccard += jaccard(&result_sets[i], &result_sets[j]);
            pair_count += 1;
        }
    }

    let avg_pairwise_jaccard = if pair_count > 0 {
        sum_jaccard / f64::from(pair_count)
    } else {
        1.0
    };

    TargetProbe {
        avg_pairwise_jaccard,
        response_rate,
        nonempty_sets,
    }
}

/// Enhanced DHT warmup: query random targets from every node.
async fn enhanced_warmup(harness: &TestHarness, num_addresses: usize, k: usize) {
    let addresses = random_xor_names(num_addresses);
    for i in 0..harness.node_count() {
        if let Some(p2p) = harness.node(i) {
            for addr in &addresses {
                let _ = p2p.dht().find_closest_nodes(addr, k).await;
            }
        }
    }
}

/// Run reachability check.
async fn check_reachability(harness: &TestHarness) {
    let probes = random_xor_names(harness.node_count());
    let mut unreachable = 0usize;

    for (i, probe) in probes.iter().enumerate() {
        if let Some(p2p) = harness.node(i) {
            match p2p.dht().find_closest_nodes(probe, K).await {
                Ok(peers) if peers.len() >= MIN_REACHABLE_PEERS => {}
                Ok(peers) => {
                    eprintln!("  Node {i}: found only {} peers", peers.len());
                    unreachable += 1;
                }
                Err(e) => {
                    eprintln!("  Node {i}: DHT query failed: {e}");
                    unreachable += 1;
                }
            }
        }
    }

    let max_unreachable = NODE_COUNT / 5;
    assert!(
        unreachable <= max_unreachable,
        "{unreachable} nodes failed reachability (max {max_unreachable})"
    );
    eprintln!("  Reachability: {unreachable}/{NODE_COUNT} below threshold (max {max_unreachable})");
}

/// Run full DHT warmup sequence.
async fn run_warmup(harness: &TestHarness) {
    eprintln!("  DHT warmup: standard round…");
    harness
        .warmup_dht()
        .await
        .expect("DHT standard warmup failed");

    for round in 1..=WARMUP_ROUNDS {
        eprintln!(
            "  DHT warmup: enhanced round {round}/{WARMUP_ROUNDS} \
             ({WARMUP_RANDOM_ADDRESSES} addrs, k={K})…"
        );
        enhanced_warmup(harness, WARMUP_RANDOM_ADDRESSES, K).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    eprintln!("  DHT warmup: settling…");
    tokio::time::sleep(Duration::from_secs(5)).await;
}

/// Run convergence probes and return per-target results.
async fn run_convergence_probes(harness: &TestHarness) -> Vec<TargetProbe> {
    let targets = random_xor_names(NUM_TARGETS);
    let node_count = harness.node_count();

    let all_indices: Vec<usize> = (0..node_count).collect();
    let observer_selections: Vec<Vec<usize>> = {
        let mut rng = rand::thread_rng();
        targets
            .iter()
            .map(|_| {
                let mut candidates = all_indices.clone();
                candidates.shuffle(&mut rng);
                candidates.into_iter().take(NUM_OBSERVERS).collect()
            })
            .collect()
    };

    let mut results = Vec::with_capacity(NUM_TARGETS);

    for (idx, target) in targets.iter().enumerate() {
        let observers = &observer_selections[idx];
        let probe = probe_target(harness, target, observers).await;

        eprintln!(
            "  Target {:>2} ({}…): pairwise_jaccard={:.3}, response={:.2}, observers={}",
            idx,
            &hex::encode(target)[..12],
            probe.avg_pairwise_jaccard,
            probe.response_rate,
            probe.nonempty_sets,
        );

        results.push(probe);
    }

    results
}

// ---------------------------------------------------------------------------
// Main test
// ---------------------------------------------------------------------------

/// Verify that a 100-node network's DHT lookups converge — different nodes
/// querying the same key should find similar closest peers.
#[tokio::test(flavor = "multi_thread")]
async fn test_100_node_network_convergence() {
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        bootstrap_count: BOOTSTRAP_COUNT,
        spawn_delay: Duration::from_millis(150),
        stabilization_timeout: Duration::from_secs(300),
        node_startup_timeout: Duration::from_secs(60),
        ..Default::default()
    };

    eprintln!("Starting {NODE_COUNT}-node network…");
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert!(harness.is_ready().await, "Network should be ready");
    assert_eq!(harness.node_count(), NODE_COUNT);

    let total_conns = harness.total_connections().await;
    assert!(total_conns > 0, "Network should have connections");
    eprintln!("  Network ready — {total_conns} total connections");

    run_warmup(&harness).await;

    eprintln!("  Checking DHT reachability…");
    check_reachability(&harness).await;

    eprintln!("  Running {NUM_TARGETS} convergence probes ({NUM_OBSERVERS} observers each)…");
    let probes = run_convergence_probes(&harness).await;
    assert_convergence(&probes);

    eprintln!("  Network convergence verified");
    harness.teardown().await.expect("Failed to teardown");
}

/// Assert convergence metrics meet thresholds.
fn assert_convergence(probes: &[TargetProbe]) {
    assert!(!probes.is_empty(), "No probes evaluated");

    #[allow(clippy::cast_precision_loss)]
    let n = probes.len() as f64;

    let avg_jaccard = probes.iter().map(|p| p.avg_pairwise_jaccard).sum::<f64>() / n;
    let avg_response = probes.iter().map(|p| p.response_rate).sum::<f64>() / n;
    let min_jaccard = probes
        .iter()
        .map(|p| p.avg_pairwise_jaccard)
        .reduce(f64::min)
        .unwrap_or(0.0);
    let max_jaccard = probes
        .iter()
        .map(|p| p.avg_pairwise_jaccard)
        .reduce(f64::max)
        .unwrap_or(0.0);

    eprintln!();
    eprintln!("  ╔══════════════════════════════════════════════════╗");
    eprintln!("  ║       LOOKUP PATH CONVERGENCE SUMMARY           ║");
    eprintln!("  ╠══════════════════════════════════════════════════╣");
    eprintln!(
        "  ║  Targets probed:           {:>4}                 ║",
        probes.len()
    );
    eprintln!("  ║  Avg pairwise Jaccard:     {avg_jaccard:.3}                ║");
    eprintln!("  ║  Min pairwise Jaccard:     {min_jaccard:.3}                ║");
    eprintln!("  ║  Max pairwise Jaccard:     {max_jaccard:.3}                ║");
    eprintln!("  ║  Avg response rate:        {avg_response:.3}                ║");
    eprintln!("  ╚══════════════════════════════════════════════════╝");
    eprintln!();

    assert!(
        avg_response >= MIN_RESPONSE_RATE,
        "Avg response rate {avg_response:.3} < {MIN_RESPONSE_RATE} — \
         too many observers returned empty results"
    );

    assert!(
        avg_jaccard >= MIN_AVG_PAIRWISE_JACCARD,
        "Avg pairwise Jaccard {avg_jaccard:.3} < {MIN_AVG_PAIRWISE_JACCARD} — \
         lookups from different nodes diverge (possible network partition)"
    );
}
