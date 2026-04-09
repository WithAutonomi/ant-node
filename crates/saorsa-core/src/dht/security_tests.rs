use crate::PeerId;
use crate::dht::core_engine::{AtomicInstant, DhtCoreEngine, NodeInfo};
use crate::security::IPDiversityConfig;

/// Helper: create a NodeInfo with a specific PeerId (from byte array) and address.
fn make_node_with_id(id_bytes: [u8; 32], addr: &str) -> NodeInfo {
    NodeInfo {
        id: PeerId::from_bytes(id_bytes),
        addresses: vec![addr.parse().unwrap()],
        last_seen: AtomicInstant::now(),
        address_types: vec![],
    }
}

/// Build a deterministic peer ID that lands in bucket 0 when self=[0;32].
///
/// All returned IDs have `id[0] = 0x80` (so XOR with [0;32] has its first
/// set bit at position 0 -> bucket 0). `seq` is written to `id[31]` for
/// uniqueness within the bucket.
fn bucket0_id(seq: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0x80;
    id[31] = seq;
    id
}

// -----------------------------------------------------------------------
// IPv6 diversity -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv6() -> anyhow::Result<()> {
    // With self=[0;32], all nodes land in bucket 0.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Subnet limit = K/4 = 20/4 = 5. Add 5 nodes in same /48 — all should succeed.
    for i in 1..=5u8 {
        let node = make_node_with_id(bucket0_id(i), &format!("/ip6/2001:db8::{i}/udp/9000/quic"));
        engine.add_node_no_trust(node).await?;
    }

    // Sixth node in same /48 should fail (exceeds /48 limit of 5).
    let node6 = make_node_with_id(bucket0_id(6), "/ip6/2001:db8::6/udp/9000/quic");
    let result = engine.add_node_no_trust(node6).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 diversity -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ip_diversity_enforcement_ipv4() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/192.168.1.1/udp/9000/quic");
    engine.add_node_no_trust(node1).await?;

    // Second same-IP node should succeed (exact-IP limit = 2).
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/192.168.1.1/udp/9001/quic");
    engine.add_node_no_trust(node2).await?;

    // Third same-IP node should fail (exceeds exact-IP limit of 2).
    let node3 = make_node_with_id(bucket0_id(3), "/ip4/192.168.1.1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 /24 subnet limit -- per-bucket enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_subnet_24_limit() -> anyhow::Result<()> {
    // Subnet limit = K/4 = 20/4 = 5.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Five nodes on different IPs but same /24, all in bucket 0.
    for i in 1..=5u8 {
        engine
            .add_node_no_trust(make_node_with_id(
                bucket0_id(i),
                &format!("/ip4/192.168.1.{i}/udp/9000/quic"),
            ))
            .await?;
    }

    // Sixth should fail (/24 limit = 5).
    let node6 = make_node_with_id(bucket0_id(6), "/ip4/192.168.1.6/udp/9000/quic");
    let result = engine.add_node_no_trust(node6).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "Error should indicate IP diversity limits"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// Mixed IPv4 + IPv6 enforcement
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_mixed_ipv4_ipv6_enforcement() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // IPv4 node
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // IPv6 node -- different address family, should succeed
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;

    // Second IPv4 on same IP should succeed (exact-IP limit = 2)
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(3),
            "/ip4/192.168.1.1/udp/9001/quic",
        ))
        .await?;

    // Third IPv4 on same IP should fail (exceeds exact-IP limit of 2)
    let result_v4 = engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(4),
            "/ip4/192.168.1.1/udp/9002/quic",
        ))
        .await;
    assert!(result_v4.is_err());

    // IPv6 nodes in same /48 should succeed up to the /48 limit (K/4 = 5).
    // We already added one IPv6 node above (bucket0_id(2)), so add 4 more.
    for i in 5..=8u8 {
        engine
            .add_node_no_trust(make_node_with_id(
                bucket0_id(i),
                &format!("/ip6/2001:db8::{i}/udp/9000/quic"),
            ))
            .await?;
    }

    // Sixth IPv6 in same /48 should fail (exceeds /48 limit of 5)
    let result_v6 = engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(9),
            "/ip6/2001:db8::9/udp/9000/quic",
        ))
        .await;
    assert!(result_v6.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_ip_override_raises_limit() -> anyhow::Result<()> {
    // Default exact-IP limit is 2.
    // Setting max_per_ip = 3 should allow 3 nodes on the same IP.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_ip: Some(3),
        max_per_subnet: Some(usize::MAX),
    });

    for i in 1..=3u8 {
        let node = make_node_with_id(
            bucket0_id(i),
            &format!("/ip4/192.168.1.1/udp/{}/quic", 9000 + u16::from(i)),
        );
        engine.add_node_no_trust(node).await?;
    }

    // Fourth node should fail (max_per_ip = 3)
    let node4 = make_node_with_id(bucket0_id(4), "/ip4/192.168.1.1/udp/9003/quic");
    let result = engine.add_node_no_trust(node4).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_subnet_override_lowers_limit() -> anyhow::Result<()> {
    // Setting max_per_subnet = 1 caps /24 limit at 1.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(1),
        ..IPDiversityConfig::default()
    });

    let node1 = make_node_with_id(bucket0_id(1), "/ip4/10.0.1.1/udp/9000/quic");
    engine.add_node_no_trust(node1).await?;

    // Different IP but same /24 -- should fail because /24 limit = 1
    let node2 = make_node_with_id(bucket0_id(2), "/ip4/10.0.1.2/udp/9000/quic");
    let result = engine.add_node_no_trust(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 floor override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_subnet_override_raises_limit() -> anyhow::Result<()> {
    // Default subnet limit is K/4 = 20/4 = 5. Setting max_per_subnet = 8
    // should allow 8 nodes in the same /48 subnet.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(8),
        ..IPDiversityConfig::default()
    });

    for i in 1..=8u8 {
        let node = make_node_with_id(bucket0_id(i), &format!("/ip6/2001:db8::{i}/udp/9000/quic"));
        engine.add_node_no_trust(node).await?;
    }

    // Ninth node should fail
    let node9 = make_node_with_id(bucket0_id(9), "/ip6/2001:db8::9/udp/9000/quic");
    let result = engine.add_node_no_trust(node9).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 ceiling override
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_subnet_override_lowers_limit() -> anyhow::Result<()> {
    // Default subnet limit is K/4 = 20/4 = 5. Setting max_per_subnet = 1 lowers it.
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig {
        max_per_subnet: Some(1),
        ..IPDiversityConfig::default()
    });

    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;

    // Second should fail because /48 limit is now 1
    let node2 = make_node_with_id(bucket0_id(2), "/ip6/2001:db8::2/udp/9000/quic");
    let result = engine.add_node_no_trust(node2).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("IP diversity:"));

    Ok(())
}

// -----------------------------------------------------------------------
// No overrides -- defaults enforced
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_no_override_uses_defaults() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;

    // Second same-IP should succeed (exact-IP limit = 2)
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip4/192.168.1.1/udp/9001/quic",
        ))
        .await?;

    // Third same-IP should fail (exceeds exact-IP limit of 2)
    let node3 = make_node_with_id(bucket0_id(3), "/ip4/192.168.1.1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(result.is_err());

    Ok(())
}

// -----------------------------------------------------------------------
// Trust-aware swap-closer protection
// -----------------------------------------------------------------------

/// A well-trusted peer (score >= 0.7) should keep its routing table slot
/// even when a closer same-IP candidate arrives that would normally evict it.
#[tokio::test]
async fn test_trust_protects_peer_from_swap() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::default());

    // Two peers in bucket 0, same IP (exact-IP limit = 2).
    let mut id_far = [0u8; 32];
    id_far[0] = 0xFF; // farthest from self=[0;32]
    engine
        .add_node_no_trust(make_node_with_id(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;

    let mut id_mid = [0u8; 32];
    id_mid[0] = 0xFE;
    engine
        .add_node_no_trust(make_node_with_id(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
        .await?;

    // A closer candidate with the same IP tries to join.
    // The farthest peer (id_far) has trust 0.8 — above TRUST_PROTECTION_THRESHOLD.
    let mut id_close = [0u8; 32];
    id_close[0] = 0x80; // closer to self than id_far/id_mid
    let far_peer = PeerId::from_bytes(id_far);

    let trust_fn = |peer_id: &PeerId| -> f64 {
        if *peer_id == far_peer {
            0.8 // trusted — above threshold
        } else {
            0.5 // neutral
        }
    };

    let result = engine
        .add_node(
            make_node_with_id(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
            &trust_fn,
        )
        .await;

    // Should be REJECTED: the only swap candidate (farthest) is trust-protected
    assert!(result.is_err());
    assert!(engine.has_node(&far_peer).await);
    // id_mid must also survive — trust protection should not redirect the swap to it
    assert!(engine.has_node(&PeerId::from_bytes(id_mid)).await);

    Ok(())
}

/// An untrusted peer (score < 0.7) should be swapped out when a closer
/// same-IP candidate arrives, preserving the original distance-based behavior.
#[tokio::test]
async fn test_untrusted_peer_can_be_swapped() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    engine.set_ip_diversity_config(IPDiversityConfig::default());

    let mut id_far = [0u8; 32];
    id_far[0] = 0xFF;
    engine
        .add_node_no_trust(make_node_with_id(id_far, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;

    let mut id_mid = [0u8; 32];
    id_mid[0] = 0xFE;
    engine
        .add_node_no_trust(make_node_with_id(id_mid, "/ip4/10.0.1.1/udp/9001/quic"))
        .await?;

    let mut id_close = [0u8; 32];
    id_close[0] = 0x80;
    let far_peer = PeerId::from_bytes(id_far);

    let trust_fn = |peer_id: &PeerId| -> f64 {
        if *peer_id == far_peer {
            0.3 // low trust — below threshold
        } else {
            0.5
        }
    };

    let result = engine
        .add_node(
            make_node_with_id(id_close, "/ip4/10.0.1.1/udp/9002/quic"),
            &trust_fn,
        )
        .await;

    // Should succeed — far peer is not trust-protected and gets swapped out
    assert!(result.is_ok());
    assert!(engine.has_node(&PeerId::from_bytes(id_close)).await);
    assert!(!engine.has_node(&far_peer).await);
    // id_mid must also survive — only the farthest untrusted peer is swapped
    assert!(engine.has_node(&PeerId::from_bytes(id_mid)).await);

    Ok(())
}

// -----------------------------------------------------------------------
// Self-insertion rejection
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_self_insertion_rejected() -> anyhow::Result<()> {
    let self_id = PeerId::from_bytes([0u8; 32]);
    let mut engine = DhtCoreEngine::new_for_tests(self_id)?;

    let self_node = NodeInfo {
        id: self_id,
        addresses: vec!["/ip4/10.0.0.1/udp/9000/quic".parse().unwrap()],
        last_seen: AtomicInstant::now(),
        address_types: vec![],
    };
    let result = engine.add_node_no_trust(self_node).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("cannot add self"),
        "expected self-insertion rejection"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv4-mapped IPv6 canonicalization — must count against IPv4 limits
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv4_mapped_ipv6_counts_as_ipv4() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Exact-IP limit is 2. Add two nodes using the native IPv4 form.
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip4/192.168.1.1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip4/192.168.1.1/udp/9001/quic",
        ))
        .await?;

    // Third node uses IPv4-mapped IPv6 form of the same IP: ::ffff:192.168.1.1
    // This must be canonicalized and rejected as the third same-IP node.
    let node3 = make_node_with_id(bucket0_id(3), "/ip6/::ffff:192.168.1.1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(
        result.is_err(),
        "IPv4-mapped IPv6 should be treated as IPv4 and hit the exact-IP limit"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// IPv6 exact-IP limit
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_ipv6_exact_ip_limit() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Exact-IP limit is 2. Two nodes with the same IPv6 address should succeed.
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(1),
            "/ip6/2001:db8::1/udp/9000/quic",
        ))
        .await?;
    engine
        .add_node_no_trust(make_node_with_id(
            bucket0_id(2),
            "/ip6/2001:db8::1/udp/9001/quic",
        ))
        .await?;

    // Third with the same IPv6 address should fail (exact-IP limit = 2).
    let node3 = make_node_with_id(bucket0_id(3), "/ip6/2001:db8::1/udp/9002/quic");
    let result = engine.add_node_no_trust(node3).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("exact-IP"),
        "expected exact-IP rejection for IPv6"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// Swap rejection when candidate is farther
// -----------------------------------------------------------------------

#[tokio::test]
async fn test_farther_candidate_cannot_swap() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;

    // Two nodes on the same IP in bucket 0, both close to self.
    let mut id1 = [0u8; 32];
    id1[0] = 0x80;
    id1[31] = 0x01; // closer
    let mut id2 = [0u8; 32];
    id2[0] = 0x80;
    id2[31] = 0x02;

    engine
        .add_node_no_trust(make_node_with_id(id1, "/ip4/10.0.1.1/udp/9000/quic"))
        .await?;
    engine
        .add_node_no_trust(make_node_with_id(id2, "/ip4/10.0.1.1/udp/9001/quic"))
        .await?;

    // Third same-IP node that is FARTHER than both existing nodes.
    // XOR distance [0xFF, 0, ..., 0] > [0x80, 0, ..., 0x02].
    let mut id_far = [0u8; 32];
    id_far[0] = 0xFF;
    let result = engine
        .add_node_no_trust(make_node_with_id(id_far, "/ip4/10.0.1.1/udp/9002/quic"))
        .await;
    assert!(
        result.is_err(),
        "farther candidate should not be able to swap in"
    );
    assert!(
        result.unwrap_err().to_string().contains("IP diversity:"),
        "expected IP diversity rejection"
    );

    // Both original nodes must survive
    assert!(engine.has_node(&PeerId::from_bytes(id1)).await);
    assert!(engine.has_node(&PeerId::from_bytes(id2)).await);

    Ok(())
}

// -----------------------------------------------------------------------
// Close-group IP diversity enforcement
// -----------------------------------------------------------------------

/// Build a peer ID that lands in a specific bucket when self=[0;32].
/// The differing bit is at position `bucket`, all other bits zero except
/// `seq` in the last byte for uniqueness.
fn id_in_bucket(bucket: usize, seq: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    let byte_idx = bucket / 8;
    let bit_idx = 7 - (bucket % 8);
    id[byte_idx] = 1 << bit_idx;
    id[31] |= seq; // uniqueness within bucket
    id
}

/// Close-group diversity: when the K closest nodes to self span multiple
/// buckets, the IP diversity limit should be enforced across the combined
/// group — not just per-bucket.
#[tokio::test]
async fn test_close_group_ip_diversity_rejects_excess() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    // K=20 for tests, subnet limit = 20/4 = 5.

    // Place 5 nodes on the same /24 across different high-numbered buckets
    // (closest to self). Each is the sole node in its bucket, so per-bucket
    // limits are never hit, but the close group as a whole has 5 same-/24 peers.
    for i in 0..5u8 {
        let bucket = 255 - (i as usize); // buckets 255, 254, 253, 252, 251
        let id = id_in_bucket(bucket, 0);
        engine
            .add_node_no_trust(make_node_with_id(
                id,
                &format!("/ip4/10.0.1.{}/udp/9000/quic", i + 1),
            ))
            .await?;
    }

    // 6th same-/24 node in a close bucket — per-bucket is fine (1 node) but
    // close-group /24 count is now 6 which exceeds the limit of 5.
    let id6 = id_in_bucket(250, 0);
    let result = engine
        .add_node_no_trust(make_node_with_id(id6, "/ip4/10.0.1.6/udp/9000/quic"))
        .await;
    assert!(
        result.is_err(),
        "close-group /24 limit should reject 6th same-subnet peer"
    );
    assert!(
        result.unwrap_err().to_string().contains("close-group"),
        "expected close-group rejection"
    );

    Ok(())
}

/// Close-group swap-closer: a closer same-subnet peer should evict the
/// farthest same-subnet peer from the close group even when per-bucket
/// limits are not exceeded.
#[tokio::test]
async fn test_close_group_swap_closer_evicts_farthest() -> anyhow::Result<()> {
    let mut engine = DhtCoreEngine::new_for_tests(PeerId::from_bytes([0u8; 32]))?;
    // K=20, subnet limit = 5.

    // 5 same-/24 peers in close group, each in its own bucket.
    // The farthest is in bucket 251 (5th closest).
    let mut peer_ids = Vec::new();
    for i in 0..5u8 {
        let bucket = 255 - (i as usize);
        let id = id_in_bucket(bucket, 0);
        peer_ids.push(id);
        engine
            .add_node_no_trust(make_node_with_id(
                id,
                &format!("/ip4/10.0.1.{}/udp/9000/quic", i + 1),
            ))
            .await?;
    }

    // New same-/24 peer that is CLOSER than the farthest close-group member
    // (bucket 251). Place it in bucket 249 — farther than bucket 251 in
    // XOR distance. Instead, place at bucket 256-1 = 255... no, bucket 255 is
    // taken. Let's use a different approach: add the 6th peer in a bucket
    // that is closer to self than bucket 251.
    //
    // Actually, bucket 255 is the closest to self (smallest XOR distance).
    // We already used buckets 255..251 for the 5 peers. The 6th peer at
    // bucket 250 is farther than all 5 — this would NOT swap.
    //
    // For a successful swap test, we need the new peer closer than the
    // farthest existing close-group peer. The farthest is at bucket 251
    // (i=4). Let's put the new peer at bucket 253 (closer than 251):
    // But 253 is already taken (i=2).
    //
    // Use a different uniqueness byte so the new peer also lands in bucket 253.
    let id_closer = id_in_bucket(253, 1); // same bucket as i=2, different seq
    let farthest_id = PeerId::from_bytes(peer_ids[4]); // bucket 251

    // This peer has a different /24 from the existing ones but same IP
    // to trigger exact-IP... no, let's keep the same /24.
    let result = engine
        .add_node_no_trust(make_node_with_id(id_closer, "/ip4/10.0.1.7/udp/9000/quic"))
        .await;

    // Should succeed by swapping out the farthest same-/24 peer in the close group.
    assert!(
        result.is_ok(),
        "closer same-subnet peer should swap in: {:?}",
        result
    );
    assert!(engine.has_node(&PeerId::from_bytes(id_closer)).await);
    assert!(
        !engine.has_node(&farthest_id).await,
        "farthest same-subnet peer should have been evicted from close group"
    );

    Ok(())
}
