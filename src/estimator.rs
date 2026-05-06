//! Network size estimator.
//!
//! Bootstraps a saorsa-core `P2PNode` in client mode, performs many random-key
//! iterative `FIND_NODE` lookups, and infers the live network size from the
//! XOR distance to the k-th closest peer in each lookup.
//!
//! The per-sample estimator is the standard Kademlia density estimator
//! `N̂ = k · 2^256 / d_k`, where `d_k` is the XOR distance from the random
//! target to the k-th closest peer found. Averaging over many random targets
//! reduces variance; this is the largest source of accuracy improvement
//! available to a single vantage point.
//!
//! Implementation note on precision: `d_k` is a 256-bit XOR distance, but
//! `f64` has only 53 bits of mantissa, so we evaluate the formula on the
//! leading 64 bits of `d_k` — equivalent to `k · 2^64 / d_top64`. For any
//! realistic network size (≪ 2^53), the leading-64-bit truncation drops
//! only mantissa-level bits and has no measurable effect on the estimate.
//!
//! The estimator runs in `NodeMode::Client`, so it does not participate in
//! DHT routing, does not open a listening socket, and exits as soon as the
//! lookups complete.

// The estimator's math operates on f64 approximations of large integers
// (sample counts, 256-bit XOR distances) where mantissa precision and
// truncation are intentional, not bugs.
#![allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]

use crate::config::{NetworkMode, NodeConfig};
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use saorsa_core::{
    IPDiversityConfig as CoreDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, NodeMode,
    P2PNode,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Parameters controlling an estimator run.
#[derive(Debug, Clone, Copy)]
pub struct EstimatorParams {
    /// Number of random-key samples to take. Standard error scales as 1/√n.
    pub samples: usize,
    /// Kademlia `k` (closest-peer count per lookup). When 0, uses the
    /// saorsa-core default (`DhtNetworkManager::k_value()`).
    pub k: usize,
    /// Per-lookup timeout.
    pub lookup_timeout: Duration,
    /// Bootstrap-completion timeout.
    pub bootstrap_timeout: Duration,
    /// Print per-sample diagnostics as samples complete.
    pub verbose: bool,
}

impl Default for EstimatorParams {
    fn default() -> Self {
        Self {
            samples: 32,
            k: 0,
            // Matches the CLI default; saorsa-core's iterative lookup can
            // take this long when a dead peer's dial cascade drags out an
            // early iteration.
            lookup_timeout: Duration::from_secs(90),
            bootstrap_timeout: Duration::from_secs(60),
            verbose: false,
        }
    }
}

/// Result of an estimator run.
#[derive(Debug, Clone)]
pub struct SizeEstimate {
    /// Arithmetic mean of per-sample estimates.
    pub mean: f64,
    /// Median of per-sample estimates (robust to skew).
    pub median: f64,
    /// 95% confidence interval lower bound (mean − 1.96·SE).
    pub ci_low: f64,
    /// 95% confidence interval upper bound (mean + 1.96·SE).
    pub ci_high: f64,
    /// Number of samples attempted.
    pub samples_attempted: usize,
    /// Number of samples that produced a usable density estimate.
    pub samples_successful: usize,
    /// Kademlia `k` used (resolved if 0 was passed).
    pub k_used: usize,
}

/// Estimate the size of the live network.
///
/// # Errors
///
/// Returns an error if the client-mode `P2PNode` cannot be built or
/// bootstrapped, or if no samples produced a usable density estimate.
pub async fn estimate_network_size(
    config: &NodeConfig,
    params: EstimatorParams,
) -> Result<SizeEstimate> {
    if params.samples == 0 {
        return Err(Error::Config("estimator requires samples > 0".to_string()));
    }

    let core_config = build_client_core_config(config)?;
    debug!("Estimator core config: {:?}", core_config);

    eprintln!(
        "Connecting to bootstrap peers ({} configured)... [this can take 30\u{2013}60s]",
        config.bootstrap.len()
    );
    let p2p_node = P2PNode::new(core_config)
        .await
        .map_err(|e| Error::Startup(format!("Failed to create client P2P node: {e}")))?;
    let p2p = Arc::new(p2p_node);

    info!("Starting client-mode node for network size estimation");
    let bootstrap_started = Instant::now();
    p2p.start()
        .await
        .map_err(|e| Error::Startup(format!("Failed to start client P2P node: {e}")))?;
    eprintln!(
        "p2p.start() returned in {:.1}s (is_bootstrapped={})",
        bootstrap_started.elapsed().as_secs_f64(),
        p2p.is_bootstrapped()
    );

    wait_for_bootstrap(&p2p, params.bootstrap_timeout).await?;

    let dht = p2p.dht_manager();
    let rt_size = dht.get_routing_table_size().await;
    eprintln!("Routing table populated with {rt_size} peer(s).");
    if rt_size == 0 {
        return Err(Error::Startup(
            "routing table is empty after bootstrap \u{2014} bootstrap peers may be unreachable"
                .to_string(),
        ));
    }

    let k_used = if params.k == 0 {
        dht.k_value()
    } else {
        params.k
    };
    if rt_size < k_used {
        eprintln!(
            "Warning: routing table has only {rt_size} peer(s) but k={k_used}; \
             samples may be discarded. Consider --k {rt_size} or fewer."
        );
    }
    eprintln!(
        "Running {} random-key lookups (k={})...",
        params.samples, k_used
    );
    info!(
        samples = params.samples,
        k = k_used,
        "Running random-key lookups for size estimation"
    );

    let started = Instant::now();
    let per_sample = run_sample_loop(&p2p, k_used, &params).await;
    let elapsed = started.elapsed();
    eprintln!(
        "Sampling complete: {}/{} successful in {:.1}s",
        per_sample.len(),
        params.samples,
        elapsed.as_secs_f64()
    );
    info!(
        attempted = params.samples,
        successful = per_sample.len(),
        elapsed_ms = elapsed.as_millis() as u64,
        "Estimator sampling complete"
    );

    if per_sample.is_empty() {
        return Err(Error::Startup(
            "no samples produced a usable density estimate (all lookups failed or returned too few peers)"
                .to_string(),
        ));
    }

    Ok(aggregate(per_sample, params.samples, k_used))
}

/// Run the per-sample lookup loop. Each sample picks a fresh random
/// 32-byte target key, performs a single iterative `FIND_NODE`, and
/// derives a per-sample density estimate. Failures (timeouts, errors,
/// too-few-peers) are reported on stderr and skipped. Returns only the
/// successful per-sample estimates.
async fn run_sample_loop(p2p: &Arc<P2PNode>, k_used: usize, params: &EstimatorParams) -> Vec<f64> {
    let dht = p2p.dht_manager();
    let mut per_sample: Vec<f64> = Vec::with_capacity(params.samples);

    for sample_idx in 0..params.samples {
        // `rand::random()` is scoped to a single statement so its
        // non-Send `ThreadRng` is dropped before the next await,
        // keeping this future `Send`.
        let key: [u8; 32] = rand::random();

        let lookup = dht.find_closest_nodes_network(&key, k_used);
        let result = match tokio::time::timeout(params.lookup_timeout, lookup).await {
            Ok(Ok(nodes)) => nodes,
            Ok(Err(e)) => {
                eprintln!(
                    "  [{}/{}] lookup failed: {e}",
                    sample_idx + 1,
                    params.samples
                );
                warn!(sample = sample_idx, error = %e, "Lookup failed");
                continue;
            }
            Err(_) => {
                eprintln!(
                    "  [{}/{}] lookup timed out after {}s",
                    sample_idx + 1,
                    params.samples,
                    params.lookup_timeout.as_secs()
                );
                warn!(sample = sample_idx, "Lookup timed out");
                continue;
            }
        };

        let Some(estimate) = sample_estimate(&key, &result, k_used) else {
            eprintln!(
                "  [{}/{}] returned only {} peer(s), need {} — skipping",
                sample_idx + 1,
                params.samples,
                result.len(),
                k_used
            );
            warn!(
                sample = sample_idx,
                returned = result.len(),
                "Lookup returned too few peers to estimate density"
            );
            continue;
        };

        if params.verbose {
            eprintln!(
                "  [{}/{}] peers={} estimate={:.0}",
                sample_idx + 1,
                params.samples,
                result.len(),
                estimate
            );
            info!(
                sample = sample_idx,
                peers_returned = result.len(),
                estimate,
                "Sample"
            );
        } else {
            eprintln!(
                "  [{}/{}] estimate={:.0}",
                sample_idx + 1,
                params.samples,
                estimate
            );
        }
        per_sample.push(estimate);
    }

    per_sample
}

/// Build a saorsa-core config for an ephemeral client-mode node.
///
/// Reuses the bootstrap peers from `NodeConfig`. Skips listen port,
/// storage, payments, and close-group cache — none of which are
/// needed for one-shot DHT lookups.
fn build_client_core_config(config: &NodeConfig) -> Result<CoreNodeConfig> {
    let local = matches!(config.network_mode, NetworkMode::Development);

    let mut core_config = CoreNodeConfig::builder()
        .port(0)
        .ipv6(!config.ipv4_only)
        .local(local)
        .mode(NodeMode::Client)
        .build()
        .map_err(|e| Error::Config(format!("Failed to create client core config: {e}")))?;

    core_config.bootstrap_peers = config
        .bootstrap
        .iter()
        .map(|addr| MultiAddr::quic(*addr))
        .collect();

    if matches!(config.network_mode, NetworkMode::Testnet) {
        core_config.allow_loopback = true;
        core_config.diversity_config = Some(CoreDiversityConfig {
            max_per_ip: config.testnet.max_per_ip,
            max_per_subnet: config.testnet.max_per_subnet,
        });
    }

    Ok(core_config)
}

async fn wait_for_bootstrap(p2p: &Arc<P2PNode>, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    let poll_interval = Duration::from_millis(200);
    let progress_interval = Duration::from_secs(5);
    let mut next_progress = progress_interval;

    while started.elapsed() < timeout {
        if p2p.is_bootstrapped() {
            let elapsed_ms = started.elapsed().as_millis() as u64;
            eprintln!("Bootstrap complete in {elapsed_ms}ms.");
            info!(elapsed_ms, "Bootstrap complete");
            return Ok(());
        }
        if started.elapsed() >= next_progress {
            eprintln!(
                "  ...still bootstrapping ({}s elapsed, timeout {}s)",
                started.elapsed().as_secs(),
                timeout.as_secs()
            );
            next_progress += progress_interval;
        }
        tokio::time::sleep(poll_interval).await;
    }

    Err(Error::Startup(format!(
        "client did not bootstrap within {} seconds",
        timeout.as_secs()
    )))
}

/// `2^64` as `f64`. Defined as a constant because `u64::MAX as f64` rounds
/// up to `2^64` and adding `1.0` to it is a no-op at `f64` precision —
/// using a named constant avoids relying on that rounding behavior.
const TWO_POW_64: f64 = (1u128 << 64) as f64;

/// Compute the per-sample density estimate from one lookup result.
///
/// Returns `None` if fewer than `k` peers were returned, or if the
/// k-th distance is zero (degenerate case — would imply collision).
fn sample_estimate(target: &[u8; 32], peers: &[saorsa_core::DHTNode], k: usize) -> Option<f64> {
    if peers.len() < k {
        return None;
    }

    // The lookup returns peers sorted by distance to the target (closest first).
    // We want the XOR distance to the k-th closest, i.e. the (k-1)th element.
    let kth = peers.get(k - 1)?;
    let kth_bytes = kth.peer_id.to_bytes();

    let dist = xor_distance(target, kth_bytes);
    let dist_top = leading_u64(&dist);
    if dist_top == 0 {
        return None;
    }

    // Normalize d_k into (0, 1] by treating its leading 64 bits as a binary
    // fraction of the keyspace, then density estimate is k / d_k_normalized
    // = k · 2^64 / d_k_top64.
    Some((k as f64) * TWO_POW_64 / (dist_top as f64))
}

fn xor_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn leading_u64(d: &[u8; 32]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&d[..8]);
    u64::from_be_bytes(buf)
}

fn aggregate(mut samples: Vec<f64>, attempted: usize, k_used: usize) -> SizeEstimate {
    let n = samples.len();
    let mean = samples.iter().sum::<f64>() / n as f64;

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2.0
    };

    let variance = if n > 1 {
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0)
    } else {
        0.0
    };
    let stderr = (variance / n as f64).sqrt();
    let ci_half = 1.96 * stderr;

    SizeEstimate {
        mean,
        median,
        ci_low: (mean - ci_half).max(0.0),
        ci_high: mean + ci_half,
        samples_attempted: attempted,
        samples_successful: n,
        k_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_single_sample() {
        let est = aggregate(vec![100.0], 1, 8);
        assert!((est.mean - 100.0).abs() < 1e-9);
        assert!((est.median - 100.0).abs() < 1e-9);
        assert!((est.ci_low - 100.0).abs() < 1e-9);
        assert!((est.ci_high - 100.0).abs() < 1e-9);
        assert_eq!(est.samples_successful, 1);
        assert_eq!(est.samples_attempted, 1);
        assert_eq!(est.k_used, 8);
    }

    #[test]
    fn aggregate_constant_samples_have_zero_ci() {
        let est = aggregate(vec![500.0; 10], 10, 8);
        assert!((est.mean - 500.0).abs() < 1e-9);
        assert!((est.median - 500.0).abs() < 1e-9);
        assert!((est.ci_high - est.ci_low).abs() < 1e-9);
    }

    #[test]
    fn aggregate_median_even_count() {
        let est = aggregate(vec![1.0, 2.0, 3.0, 4.0], 4, 8);
        assert!((est.median - 2.5).abs() < 1e-9);
    }

    #[test]
    fn aggregate_median_odd_count() {
        let est = aggregate(vec![10.0, 100.0, 1000.0], 3, 8);
        assert!((est.median - 100.0).abs() < 1e-9);
    }

    #[test]
    fn xor_distance_is_zero_for_identical() {
        let a = [0x42; 32];
        assert_eq!(xor_distance(&a, &a), [0u8; 32]);
    }

    #[test]
    fn xor_distance_is_symmetric() {
        let a = [0xaa; 32];
        let b = [0x55; 32];
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn leading_u64_extracts_top_bytes_big_endian() {
        let mut d = [0u8; 32];
        d[0] = 0x01;
        d[7] = 0xff;
        assert_eq!(leading_u64(&d), 0x0100_0000_0000_00ff);
    }

    #[test]
    fn ci_low_is_clamped_to_zero() {
        let est = aggregate(vec![1.0, 1.0, 1.0, 1.0, 1_000_000.0], 5, 8);
        assert!(est.ci_low >= 0.0);
    }
}
