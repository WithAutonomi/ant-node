//! Replication subsystem E2E tests.
//!
//! Tests the replication logic modules end-to-end, exercising cross-module
//! interactions with realistic data (real peer IDs, real chunk content
//! addresses, real stored data on disk).
//!
//! These tests validate:
//! - Routing functions with live peer topology
//! - Full verification pipeline (plan -> tally -> evaluate)
//! - Fetch pipeline with real content addresses
//! - `DiskStorage` integration (`list_keys`, `get_raw`)
//! - Audit digest computation with real chunk data
//! - Prune pass with real topology and stored data
//! - Bootstrap tracker lifecycle
//! - Neighbor sync hint construction
//! - Protocol message encode/decode round-trip

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::testnet::send_and_await_replication_response;
    use crate::TestHarness;
    use rand::Rng;
    use saorsa_node::client::{compute_address, peer_id_to_xor_name, xor_distance, XorName};
    use saorsa_node::replication::audit::{
        compute_audit_digest, sample_audit_keys, verify_audit_response, AuditKeyResult,
        ABSENT_DIGEST,
    };
    use saorsa_node::replication::bootstrap::BootstrapTracker;
    use saorsa_node::replication::fetch::{
        process_fetch_response, validate_content_address, FetchAttemptResult, FetchEntry,
        FetchQueue,
    };
    use saorsa_node::replication::neighbor_sync::hints::{
        admit_hint, compute_hints_for_peer, deduplicate_hints, AdmissionResult,
    };
    use saorsa_node::replication::neighbor_sync::session::{process_session, SessionDirection};
    use saorsa_node::replication::paid_list::PaidForList;
    use saorsa_node::replication::params::{
        AUDIT_BATCH_SIZE, CLOSE_GROUP_SIZE, PAID_LIST_CLOSE_GROUP_SIZE,
    };
    use saorsa_node::replication::protocol::{
        AuditChallengeRequest, AuditChallengeResponse, FetchRequest, FreshOfferRequest,
        FreshOfferResponse, PaidNotifyRequest, ReplicationBody, ReplicationMessage,
        SyncHintsRequest, VerifyRequest,
    };
    use saorsa_node::replication::prune::{run_prune_pass, PruneTracker};
    use saorsa_node::replication::routing;
    use saorsa_node::replication::state_machine::VerificationState;
    use saorsa_node::replication::types::{
        HintPipeline, PaidListEvidence, PeerKeyEvidence, PresenceEvidence,
    };
    use saorsa_node::replication::verification::{
        batch_verify_plans, plan_key_verification, verify_targets, KeyEvidenceTally, VerifyOutcome,
    };
    use saorsa_node::storage::{DiskStorage, DiskStorageConfig};
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    /// Number of peers to select for test subsets (bootstrap, fetch sources, etc.).
    const TEST_PEER_SUBSET_SIZE: usize = 3;

    /// Minimum connected peers required for hint exchange tests.
    const MIN_PEERS_FOR_HINT_TEST: usize = 2;

    /// Number of chunks to store for audit sampling tests.
    const AUDIT_TEST_CHUNK_COUNT: u8 = 10;

    // =========================================================================
    // Helpers
    // =========================================================================

    /// Convert a peer ID string to a deterministic `XorName` via SHA256 hash.
    ///
    /// Real peer IDs may not be hex-encoded 32-byte strings, so we hash them
    /// to produce a valid `XorName` for routing computations.
    fn peer_id_to_xor(peer_id: &str) -> XorName {
        compute_address(peer_id.as_bytes())
    }

    /// Build a routing table from a list of peer ID strings.
    fn build_routing_table(peer_ids: &[String]) -> Vec<(String, XorName)> {
        peer_ids
            .iter()
            .map(|id| (id.clone(), peer_id_to_xor(id)))
            .collect()
    }

    /// Generate deterministic test data of the given size with a seed byte.
    #[allow(clippy::cast_possible_truncation)]
    fn test_data(size: usize, seed: u8) -> Vec<u8> {
        (0..size)
            .map(|i| ((i % 256) as u8).wrapping_add(seed))
            .collect()
    }

    // =========================================================================
    // 1. Routing with live peer topology
    // =========================================================================

    /// Build a routing table from a live test network and verify close group,
    /// responsibility, and neighbor computations produce valid results.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_routing_with_live_peers() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        // Collect peer IDs from a regular node
        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(
            !peers.is_empty(),
            "Node 3 should have at least one connected peer"
        );

        // Build routing table
        let local_rt = build_routing_table(&peers);
        let self_id = &node.node_id;
        let self_xor = peer_id_to_xor(self_id);

        // Pick a key: the content address of some data
        let data = test_data(64, 0x42);
        let key = compute_address(&data);

        // close_group should return at most CLOSE_GROUP_SIZE peers
        let cg = routing::close_group(&key, &local_rt, CLOSE_GROUP_SIZE);
        assert!(cg.len() <= CLOSE_GROUP_SIZE);
        assert!(!cg.is_empty());

        // Results should be sorted by distance (nearest first)
        for window in cg.windows(2) {
            let dist_a = xor_distance(&key, &window[0].1);
            let dist_b = xor_distance(&key, &window[1].1);
            assert!(dist_a <= dist_b, "Close group should be sorted by distance");
        }

        // quorum_targets should exclude self (it operates on LocalRT)
        let qt = routing::quorum_targets(&key, &local_rt);
        assert!(qt.iter().all(|(id, _)| id != self_id));

        // quorum_needed should be at least 1
        let qn = routing::quorum_needed(qt.len());
        assert!(qn >= 1, "QuorumNeeded should be >= 1");

        // close_neighbors should return peers near self
        let neighbors = routing::close_neighbors(&self_xor, &local_rt, local_rt.len());
        assert_eq!(neighbors.len(), local_rt.len());

        // paid_close_group should include self in the evaluation
        let pcg = routing::paid_close_group(self_id, &self_xor, &key, &local_rt);
        assert!(pcg.len() <= PAID_LIST_CLOSE_GROUP_SIZE);

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 2. Full verification pipeline
    // =========================================================================

    /// Store a chunk, build routing table from live peers, plan verification,
    /// simulate evidence collection, and verify the outcome.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_verification_pipeline_with_live_topology() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        let local_rt = build_routing_table(&peers);
        let self_id = "test_self";
        let self_xor = peer_id_to_xor(self_id);

        // Store a chunk to get a real content address
        let data = test_data(256, 0xAB);
        let key = node
            .store_chunk(&data)
            .await
            .expect("Failed to store chunk");

        // Plan verification for this key
        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);

        // Verify plan structure
        assert!(
            !plan.quorum_targets.is_empty(),
            "Should have quorum targets"
        );
        assert!(plan.quorum_needed >= 1);

        // All quorum targets should be in LocalRT (excluding self)
        for (id, _) in &plan.quorum_targets {
            assert_ne!(id, self_id, "QuorumTargets should not include self");
        }

        // Compute unified verify targets — should be deduplicated
        let targets = verify_targets(&plan);
        let target_ids: HashSet<&str> = targets.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            target_ids.len(),
            targets.len(),
            "VerifyTargets should be deduplicated"
        );

        // Create a tally and simulate quorum success
        let mut tally = KeyEvidenceTally::from_plan(&plan);
        assert_eq!(tally.responded_count(), 0);

        // Feed enough positive evidence to reach quorum
        for (i, (peer_id, _)) in plan.quorum_targets.iter().enumerate() {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Present,
                    paid_list: PaidListEvidence::Unresolved,
                },
            );
            if i + 1 >= plan.quorum_needed {
                break;
            }
        }

        let outcome = tally.evaluate();
        assert!(
            matches!(outcome, VerifyOutcome::QuorumVerified { .. }),
            "Should reach quorum with enough positive evidence"
        );

        // Verify the present peers are returned
        if let VerifyOutcome::QuorumVerified { present_peers } = outcome {
            assert!(
                present_peers.len() >= plan.quorum_needed,
                "Present peers should be at least QuorumNeeded"
            );
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Test batch verification plan coalescing with multiple keys
    /// using a live network topology.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_batch_verify_with_live_topology() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        let local_rt = build_routing_table(&peers);
        let self_id = "test_self";
        let self_xor = peer_id_to_xor(self_id);

        // Store multiple chunks
        let data1 = test_data(128, 0x01);
        let data2 = test_data(128, 0x02);
        let data3 = test_data(128, 0x03);
        let key1 = node.store_chunk(&data1).await.expect("Store chunk 1");
        let key2 = node.store_chunk(&data2).await.expect("Store chunk 2");
        let key3 = node.store_chunk(&data3).await.expect("Store chunk 3");

        // Plan verification for all keys
        let plan1 =
            plan_key_verification(self_id, &self_xor, &key1, HintPipeline::Replica, &local_rt);
        let plan2 =
            plan_key_verification(self_id, &self_xor, &key2, HintPipeline::Replica, &local_rt);
        let plan3 =
            plan_key_verification(self_id, &self_xor, &key3, HintPipeline::Replica, &local_rt);

        // Batch them — should coalesce per peer
        let batches = batch_verify_plans(&[plan1, plan2, plan3]);

        // Each peer should appear at most once
        let peer_ids: Vec<&str> = batches.iter().map(|b| b.peer_id.as_str()).collect();
        let unique: HashSet<&str> = peer_ids.iter().copied().collect();
        assert_eq!(peer_ids.len(), unique.len(), "Peers should be deduplicated");

        // Total presence keys across all batches should include all 3 keys
        let all_presence_keys: HashSet<XorName> = batches
            .iter()
            .flat_map(|b| b.presence_keys.iter().copied())
            .collect();
        assert!(all_presence_keys.contains(&key1));
        assert!(all_presence_keys.contains(&key2));
        assert!(all_presence_keys.contains(&key3));

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 3. Fetch pipeline with real content addresses
    // =========================================================================

    /// Store chunks and verify the fetch pipeline correctly validates
    /// content addresses and manages the fetch queue.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_fetch_pipeline_with_real_chunks() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");
        let peers = node.connected_peers().await;

        // Store a chunk
        let data = test_data(512, 0xCC);
        let key = node.store_chunk(&data).await.expect("Store chunk");

        // Validate content addressing
        assert!(
            validate_content_address(&key, &data),
            "Real chunk data should pass content address validation"
        );
        assert!(
            !validate_content_address(&key, &test_data(512, 0xDD)),
            "Wrong data should fail content address validation"
        );

        // Build fetch queue with real XOR-based priority
        let self_xor = peer_id_to_xor(&node.node_id);
        let mut queue = FetchQueue::new(self_xor, true);
        assert!(queue.is_bootstrap_mode());

        // Enqueue with peer sources
        let sources: Vec<String> = peers.iter().take(TEST_PEER_SUBSET_SIZE).cloned().collect();
        queue.enqueue(key, sources.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.contains(&key));

        // Store another chunk and enqueue it
        let data2 = test_data(256, 0xEE);
        let key2 = node.store_chunk(&data2).await.expect("Store chunk 2");
        queue.enqueue(key2, sources);
        assert_eq!(queue.len(), 2);

        // Dequeue should give the nearest-to-self key first
        let first = queue.dequeue().expect("Should dequeue");
        let second = queue.dequeue().expect("Should dequeue second");

        let dist_first = xor_distance(&self_xor, &first.key);
        let dist_second = xor_distance(&self_xor, &second.key);
        assert!(
            dist_first <= dist_second,
            "Fetch queue should dequeue nearest-first"
        );

        // Process fetch response: success case
        let mut entry = FetchEntry::new(key, vec!["source_1".into()]);
        let result = process_fetch_response(&mut entry, "source_1", Some(data.clone()), false);
        assert_eq!(result, FetchAttemptResult::Success { key, content: data });

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 4. DiskStorage integration (list_keys, get_raw)
    // =========================================================================

    /// Store chunks via `AntProtocol`, then verify `list_keys()` and `get_raw()`
    /// return the correct data through `DiskStorage`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_disk_storage_list_keys_and_get_raw() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Store several chunks
        let data1 = test_data(64, 0x11);
        let data2 = test_data(128, 0x22);
        let data3 = test_data(256, 0x33);
        let key1 = node.store_chunk(&data1).await.expect("Store chunk 1");
        let key2 = node.store_chunk(&data2).await.expect("Store chunk 2");
        let key3 = node.store_chunk(&data3).await.expect("Store chunk 3");

        // Create a DiskStorage pointing to the same data directory
        let config = DiskStorageConfig {
            root_dir: node.data_dir.clone(),
            verify_on_read: true,
            max_chunks: 0,
        };
        let storage = DiskStorage::new(config).await.expect("Create DiskStorage");

        // list_keys() should include all stored chunks
        let stored_keys = storage.list_keys().await.expect("list_keys");
        assert!(
            stored_keys.len() >= 3,
            "Should have at least 3 keys, got {}",
            stored_keys.len()
        );
        assert!(stored_keys.contains(&key1), "Should contain key1");
        assert!(stored_keys.contains(&key2), "Should contain key2");
        assert!(stored_keys.contains(&key3), "Should contain key3");

        // get_raw() should return the exact bytes stored
        let raw1 = storage
            .get_raw(&key1)
            .await
            .expect("get_raw key1")
            .expect("key1 should exist");
        assert_eq!(raw1, data1, "Raw bytes should match original data");

        let raw2 = storage
            .get_raw(&key2)
            .await
            .expect("get_raw key2")
            .expect("key2 should exist");
        assert_eq!(raw2, data2);

        let raw3 = storage
            .get_raw(&key3)
            .await
            .expect("get_raw key3")
            .expect("key3 should exist");
        assert_eq!(raw3, data3);

        // get_raw() for a non-existent key should return None
        let nonexistent = [0xFF; 32];
        let result = storage
            .get_raw(&nonexistent)
            .await
            .expect("get_raw nonexistent");
        assert!(result.is_none());

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 5. Audit digest computation with real chunk data
    // =========================================================================

    /// Store a chunk, read raw bytes, compute and verify audit digests.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_digest_with_real_chunk_data() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Store a chunk
        let data = test_data(1024, 0x77);
        let key = node.store_chunk(&data).await.expect("Store chunk");

        // Read raw bytes via DiskStorage
        let config = DiskStorageConfig {
            root_dir: node.data_dir.clone(),
            verify_on_read: false,
            max_chunks: 0,
        };
        let storage = DiskStorage::new(config).await.expect("Create DiskStorage");
        let raw_bytes = storage
            .get_raw(&key)
            .await
            .expect("get_raw")
            .expect("Chunk should exist");

        // Compute audit digest
        let nonce = [0xAA; 32];
        let challenger_peer = "challenger_peer_1";
        let digest = compute_audit_digest(&nonce, challenger_peer, &key, &raw_bytes);

        // Digest should be deterministic
        let digest2 = compute_audit_digest(&nonce, challenger_peer, &key, &raw_bytes);
        assert_eq!(digest, digest2, "Audit digest should be deterministic");

        // Different nonce should produce different digest
        let different_nonce = [0xBB; 32];
        let digest3 = compute_audit_digest(&different_nonce, challenger_peer, &key, &raw_bytes);
        assert_ne!(
            digest, digest3,
            "Different nonce should produce different digest"
        );

        // Verify the audit response using the correct API:
        // verify_audit_response(nonce, peer_id, challenge_keys, response_digests, local_records)
        let challenge_keys = vec![key];
        let response_digests = vec![digest];
        let mut local_records: HashMap<XorName, Vec<u8>> = HashMap::new();
        local_records.insert(key, raw_bytes.clone());

        let results = verify_audit_response(
            &nonce,
            challenger_peer,
            &challenge_keys,
            &response_digests,
            &local_records,
        )
        .expect("Response length should match");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0], AuditKeyResult::Passed, "Key should pass audit");

        // Verify with wrong digest — should fail
        let wrong_digests = vec![[0x00; 32]];
        let results2 = verify_audit_response(
            &nonce,
            challenger_peer,
            &challenge_keys,
            &wrong_digests,
            &local_records,
        )
        .expect("Response length should match");

        assert_eq!(
            results2[0],
            AuditKeyResult::Absent,
            "Zero digest means absent"
        );

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Test audit key sampling with stored keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_key_sampling_with_stored_data() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Store multiple chunks to have a realistic key set
        let mut stored_keys = Vec::new();
        for seed in 0..AUDIT_TEST_CHUNK_COUNT {
            let data = test_data(64, seed);
            let key = node.store_chunk(&data).await.expect("Store chunk");
            stored_keys.push(key);
        }

        // Sample keys for audit
        let sampled = sample_audit_keys(&stored_keys, 42);
        assert!(!sampled.is_empty());
        assert!(sampled.len() <= AUDIT_BATCH_SIZE); // AUDIT_BATCH_SIZE

        // All sampled keys should be from the stored set
        for key in &sampled {
            assert!(
                stored_keys.contains(key),
                "Sampled key should be from stored set"
            );
        }

        // Different seed should produce different (or same) sample
        let sampled2 = sample_audit_keys(&stored_keys, 99);
        assert!(!sampled2.is_empty());
        assert!(sampled2.len() <= 8);

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 6. Prune pass with live topology
    // =========================================================================

    /// Store chunks, build routing table from live peers, run prune pass,
    /// and verify correct behavior for in-range and out-of-range keys.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_prune_pass_with_live_topology() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        let local_rt = build_routing_table(&peers);
        let self_id = &node.node_id;
        let self_xor = peer_id_to_xor(self_id);

        // Store chunks
        let data1 = test_data(64, 0xA1);
        let data2 = test_data(64, 0xA2);
        let key1 = node.store_chunk(&data1).await.expect("Store chunk 1");
        let key2 = node.store_chunk(&data2).await.expect("Store chunk 2");

        let stored_keys = vec![key1, key2];
        let paid_keys = vec![key1]; // Only key1 is paid

        let mut tracker = PruneTracker::default();
        let hysteresis = Duration::ZERO; // Instant pruning for test

        let result = run_prune_pass(
            self_id,
            &self_xor,
            &local_rt,
            &stored_keys,
            &paid_keys,
            &mut tracker,
            hysteresis,
        );

        // Verify no key appears in both keep and delete
        for key in &result.records_to_delete {
            // The key was determined out-of-range — verify it's truly out of range
            // (or had been out of range long enough with zero hysteresis)
            assert!(
                !routing::is_responsible(self_id, &self_xor, key, &local_rt)
                    || local_rt.len() < CLOSE_GROUP_SIZE,
                "Deleted key should be out of responsible range (unless sparse network)"
            );
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 7. Bootstrap tracker with live peers
    // =========================================================================

    /// Use real peer IDs from a live network to test bootstrap lifecycle.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_bootstrap_tracker_with_live_peers() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        // Build bootstrap peer list from real peers
        let bootstrap_peers: Vec<(String, XorName)> = peers
            .iter()
            .take(TEST_PEER_SUBSET_SIZE)
            .map(|id| (id.clone(), peer_id_to_xor(id)))
            .collect();

        let mut tracker = BootstrapTracker::new(&bootstrap_peers);
        assert_eq!(tracker.peer_count(), bootstrap_peers.len());
        assert_eq!(tracker.peers_pending(), bootstrap_peers.len());
        assert!(!tracker.is_drained());

        // Complete each peer one by one
        for (i, (peer_id, _)) in bootstrap_peers.iter().enumerate() {
            if i % 2 == 0 {
                tracker.mark_completed(peer_id);
            } else {
                tracker.mark_timed_out(peer_id);
            }
        }

        assert!(tracker.all_peers_finished());
        assert!(tracker.queues_empty());

        // Transition to drained
        let transitioned = tracker.check_drained();
        assert!(transitioned, "Should transition to drained");
        assert!(tracker.is_drained());

        // Second call should not re-transition
        assert!(!tracker.check_drained());

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 8. Neighbor sync hints with live topology
    // =========================================================================

    /// Build routing table from live peers and compute neighbor sync hints.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_neighbor_sync_hints_with_live_topology() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(
            peers.len() >= MIN_PEERS_FOR_HINT_TEST,
            "Need at least {MIN_PEERS_FOR_HINT_TEST} peers for hint test"
        );

        let local_rt = build_routing_table(&peers);
        let self_id = &node.node_id;
        let self_xor = peer_id_to_xor(self_id);
        let receiver_id = &peers[0];

        // Create some local keys
        let data1 = test_data(64, 0xF1);
        let data2 = test_data(64, 0xF2);
        let key1 = node.store_chunk(&data1).await.expect("Store chunk 1");
        let key2 = node.store_chunk(&data2).await.expect("Store chunk 2");

        let local_keys = vec![key1, key2];
        let paid_keys = vec![key1, key2];

        // Compute hints for the receiver
        let hints = compute_hints_for_peer(
            self_id,
            &self_xor,
            receiver_id,
            &local_rt,
            &local_keys,
            &paid_keys,
        );

        // Cross-set dedup: keys in both replica and paid -> only replica
        for key in &hints.replica_hints {
            assert!(
                !hints.paid_hints.contains(key),
                "Key in replica hints should not also be in paid hints (cross-set dedup)"
            );
        }

        // Test deduplication of combined hint sets
        let deduped = deduplicate_hints(&hints.replica_hints, &hints.paid_hints);
        let deduped_keys: HashSet<XorName> = deduped.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            deduped_keys.len(),
            deduped.len(),
            "Deduplicated hints should have unique keys"
        );

        // Test admission for each hinted key
        for (key, pipeline) in &deduped {
            let result = admit_hint(
                receiver_id,
                &peer_id_to_xor(receiver_id),
                key,
                *pipeline,
                &local_rt,
                false,
                false,
            );
            // Result depends on whether receiver is responsible/in paid group
            match pipeline {
                HintPipeline::Replica => {
                    assert!(
                        result == AdmissionResult::AdmittedReplica
                            || result == AdmissionResult::Rejected,
                        "Replica hint should be admitted or rejected"
                    );
                }
                HintPipeline::PaidOnly => {
                    assert!(
                        result == AdmissionResult::AdmittedPaidOnly
                            || result == AdmissionResult::Rejected,
                        "PaidOnly hint should be admitted or rejected"
                    );
                }
            }
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 9. Protocol message encode/decode round-trip
    // =========================================================================

    /// Create replication protocol messages with real chunk data and
    /// verify encode/decode round-trip integrity.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_protocol_round_trip_with_real_data() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Store a chunk to get a real content address
        let data = test_data(512, 0xDD);
        let key = node.store_chunk(&data).await.expect("Store chunk");

        // Build various replication messages with real data
        let messages = vec![
            ReplicationMessage {
                request_id: 1,
                body: ReplicationBody::FreshOffer(FreshOfferRequest {
                    key,
                    content: data.clone(),
                    proof_of_payment: vec![0xAA; 64],
                }),
            },
            ReplicationMessage {
                request_id: 2,
                body: ReplicationBody::PaidNotify(PaidNotifyRequest {
                    key,
                    proof_of_payment: vec![0xBB; 64],
                }),
            },
            ReplicationMessage {
                request_id: 3,
                body: ReplicationBody::SyncHints(SyncHintsRequest {
                    replica_hints: vec![key, [0x01; 32]],
                    paid_hints: vec![[0x02; 32]],
                    bootstrapping: false,
                }),
            },
            ReplicationMessage {
                request_id: 4,
                body: ReplicationBody::VerifyRequest(VerifyRequest {
                    presence_keys: vec![key],
                    paid_list_keys: vec![key],
                }),
            },
            ReplicationMessage {
                request_id: 5,
                body: ReplicationBody::FetchRequest(FetchRequest { key }),
            },
            ReplicationMessage {
                request_id: 6,
                body: ReplicationBody::AuditChallenge(AuditChallengeRequest {
                    challenge_id: 42,
                    nonce: [0xCC; 32],
                    keys: vec![key],
                }),
            },
        ];

        for msg in &messages {
            let encoded = msg.encode().expect("Encode should succeed");
            assert!(!encoded.is_empty(), "Encoded message should not be empty");

            let decoded = ReplicationMessage::decode(&encoded).expect("Decode should succeed");
            assert_eq!(
                msg.request_id, decoded.request_id,
                "Request ID should round-trip"
            );

            // Re-encode should produce identical bytes
            let re_encoded = decoded.encode().expect("Re-encode should succeed");
            assert_eq!(
                encoded, re_encoded,
                "Re-encoding should produce identical bytes"
            );
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 10. Full replication pipeline end-to-end
    // =========================================================================

    /// Exercise the complete replication pipeline:
    /// chunk stored -> routing computed -> verification planned ->
    /// evidence tallied -> fetch entry created -> content validated.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_full_replication_pipeline() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        let local_rt = build_routing_table(&peers);
        let self_id = &node.node_id;
        let self_xor = peer_id_to_xor(self_id);

        // Step 1: Store a chunk (simulating receipt of a fresh offer)
        let data = test_data(1024, 0xFF);
        let key = node.store_chunk(&data).await.expect("Store chunk");

        // Step 2: Plan verification
        let plan =
            plan_key_verification(self_id, &self_xor, &key, HintPipeline::Replica, &local_rt);

        // Step 3: Check local PaidForList (short-circuit)
        let mut paid_list_keys = Vec::new();
        let short_circuit = saorsa_node::replication::verification::is_locally_paid_authorized(
            &key,
            &paid_list_keys,
        );
        assert!(!short_circuit, "Key not in PaidForList yet");

        // Add key to local PaidForList
        paid_list_keys.push(key);
        let short_circuit2 = saorsa_node::replication::verification::is_locally_paid_authorized(
            &key,
            &paid_list_keys,
        );
        assert!(short_circuit2, "Key should now be locally authorized");

        // Step 4: Simulate quorum verification (without short-circuit path)
        let mut tally = KeyEvidenceTally::from_plan(&plan);
        for (peer_id, _) in &plan.quorum_targets {
            tally.record_evidence(
                peer_id,
                PeerKeyEvidence {
                    presence: PresenceEvidence::Present,
                    paid_list: PaidListEvidence::Paid,
                },
            );
        }
        let outcome = tally.evaluate();
        assert!(
            matches!(
                outcome,
                VerifyOutcome::QuorumVerified { .. } | VerifyOutcome::PaidListVerified { .. }
            ),
            "Full positive evidence should verify"
        );

        // Step 5: Extract present peers as fetch sources
        let sources = match &outcome {
            VerifyOutcome::QuorumVerified { present_peers }
            | VerifyOutcome::PaidListVerified { present_peers } => present_peers.clone(),
            _ => panic!("Expected verified outcome"),
        };
        assert!(!sources.is_empty());

        // Step 6: Create and process fetch entry
        let mut entry = FetchEntry::new(key, sources);
        let source = entry
            .next_source()
            .expect("Should have a source")
            .to_string();

        // Simulate successful fetch with correct data
        let result = process_fetch_response(&mut entry, &source, Some(data.clone()), false);
        assert_eq!(
            result,
            FetchAttemptResult::Success {
                key,
                content: data.clone(),
            },
            "Fetch with correct data should succeed"
        );

        // Step 7: Validate content address
        assert!(
            validate_content_address(&key, &data),
            "Content address validation should pass"
        );

        // Step 8: Verify DiskStorage has the chunk
        let config = DiskStorageConfig {
            root_dir: node.data_dir.clone(),
            verify_on_read: true,
            max_chunks: 0,
        };
        let storage = DiskStorage::new(config).await.expect("Create DiskStorage");
        let stored = storage
            .get_raw(&key)
            .await
            .expect("get_raw")
            .expect("Chunk should be stored");
        assert_eq!(stored, data, "Stored bytes should match original");

        // Step 9: PaidForList persistence round-trip
        let tempdir = tempfile::tempdir().expect("Create temp dir");
        let mut pfl = PaidForList::load(tempdir.path()).expect("Create PaidForList");
        pfl.add(key);
        assert!(pfl.contains(&key));
        pfl.flush().expect("PaidForList flush");

        let pfl2 = PaidForList::load(tempdir.path()).expect("PaidForList load");
        assert!(pfl2.contains(&key), "PaidForList should survive round-trip");

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 11. Cross-node chunk operations feeding replication logic
    // =========================================================================

    /// Store a chunk on one node and verify it from another, demonstrating
    /// that replication routing correctly identifies close group members.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_cross_node_replication_routing() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        // Store on node 0, get peers from both nodes 0 and 3
        let node0 = harness.test_node(0).expect("Node 0 should exist");
        let node3 = harness.test_node(3).expect("Node 3 should exist");

        let peers0 = node0.connected_peers().await;
        let peers3 = node3.connected_peers().await;

        // Both nodes should see a connected network
        assert!(!peers0.is_empty(), "Node 0 should have peers");
        assert!(!peers3.is_empty(), "Node 3 should have peers");

        // Store a chunk
        let data = test_data(128, 0x99);
        let key = node0.store_chunk(&data).await.expect("Store chunk");

        // Build routing tables from each node's perspective
        let rt0 = build_routing_table(&peers0);
        let rt3 = build_routing_table(&peers3);

        let node0_id = &node0.node_id;
        let node0_xor = peer_id_to_xor(node0_id);
        let node3_id = &node3.node_id;
        let node3_xor = peer_id_to_xor(node3_id);

        // Compute close group from each perspective
        let cg0 = routing::close_group(&key, &rt0, CLOSE_GROUP_SIZE);
        let cg3 = routing::close_group(&key, &rt3, CLOSE_GROUP_SIZE);

        // Both should identify close group members (may differ due to routing view)
        assert!(!cg0.is_empty(), "Node 0 should identify close group");
        assert!(!cg3.is_empty(), "Node 3 should identify close group");

        // Verification plans should be producible from either perspective
        let plan0 = plan_key_verification(node0_id, &node0_xor, &key, HintPipeline::Replica, &rt0);
        let plan3 = plan_key_verification(node3_id, &node3_xor, &key, HintPipeline::Replica, &rt3);

        assert!(plan0.quorum_needed >= 1);
        assert!(plan3.quorum_needed >= 1);

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 12. PaidForList persistence integration
    // =========================================================================

    /// Test `PaidForList` persistence with real content addresses.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_paid_for_list_with_real_addresses() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Store chunks to get real content addresses
        let mut keys = Vec::new();
        for seed in 0..5u8 {
            let data = test_data(64, seed);
            let key = node.store_chunk(&data).await.expect("Store chunk");
            keys.push(key);
        }

        // Create a PaidForList with these real addresses
        let tempdir = tempfile::tempdir().expect("Create temp dir");

        let mut pfl = PaidForList::load(tempdir.path()).expect("Create PaidForList");

        for key in &keys {
            pfl.add(*key);
        }

        assert_eq!(pfl.len(), keys.len());
        for key in &keys {
            assert!(pfl.contains(key));
        }

        // Flush to disk
        pfl.flush().expect("Flush PaidForList");

        // Load from disk and verify
        let loaded = PaidForList::load(tempdir.path()).expect("Load PaidForList");
        assert_eq!(loaded.len(), keys.len());
        for key in &keys {
            assert!(
                loaded.contains(key),
                "Loaded PaidForList should contain all keys"
            );
        }

        // Remove a key
        let mut pfl2 = loaded;
        pfl2.remove(&keys[0]);
        assert!(!pfl2.contains(&keys[0]));
        assert_eq!(pfl2.len(), keys.len() - 1);

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 13. State machine transitions with realistic context
    // =========================================================================

    /// Test verification state machine lifecycle transitions
    /// using real content addresses and peer IDs.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_state_machine_lifecycle_with_real_data() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node = harness.test_node(3).expect("Node 3 should exist");
        let peers = node.connected_peers().await;
        assert!(!peers.is_empty());

        // Store chunk for real address
        let data = test_data(256, 0x88);
        let key = node.store_chunk(&data).await.expect("Store chunk");

        // Start in Idle, receive offer
        let state = VerificationState::Idle;
        let state = state
            .receive_offer(key, HintPipeline::Replica)
            .expect("receive_offer");
        assert_eq!(state.name(), "OfferReceived");

        // Accept for verification
        let state = state.accept_for_verify().expect("accept_for_verify");
        assert_eq!(state.name(), "PendingVerify");

        // Quorum verified with real peer sources
        let sources: Vec<String> = peers
            .iter()
            .take(MIN_PEERS_FOR_HINT_TEST)
            .cloned()
            .collect();
        let state = state
            .quorum_verified(sources.clone())
            .expect("quorum_verified");
        assert_eq!(state.name(), "QuorumVerified");

        // Queue for fetch
        let state = state
            .queue_for_fetch_from_quorum()
            .expect("queue_for_fetch_from_quorum");
        assert_eq!(state.name(), "QueuedForFetch");

        // Start fetch
        let fetch_source = sources[0].clone();
        let state = state.start_fetch(fetch_source).expect("start_fetch");
        assert_eq!(state.name(), "Fetching");

        // Store success
        let state = state.store_success().expect("store_success");
        assert_eq!(state.name(), "Stored");

        // Verify key is preserved through transitions
        assert_eq!(state.key(), Some(&key));

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 14. Fresh offer delivery over P2P
    // =========================================================================

    /// Send a `FreshOffer` message between two live nodes and verify the
    /// round-trip: the receiver either accepts and stores the chunk, or
    /// rejects with a valid reason.
    ///
    /// Also tests rejection path: an offer with empty PoP must be rejected.
    ///
    /// Design doc coverage: Section 6.1 rules 1-7, Section 7.3, Section 10,
    /// test matrix scenarios 1, 2.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_fresh_offer_over_p2p() {
        let mut harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        // Enable replication routing on nodes 3 and 4
        let node_a_index = 3;
        let node_b_index = 4;

        harness
            .network_mut()
            .node_mut(node_b_index)
            .expect("Node B must exist")
            .enable_replication_routing();
        harness
            .network_mut()
            .node_mut(node_b_index)
            .expect("Node B must exist")
            .update_routing_view()
            .await;

        // Also enable on node A so it can receive if needed
        harness
            .network_mut()
            .node_mut(node_a_index)
            .expect("Node A must exist")
            .enable_replication_routing();
        harness
            .network_mut()
            .node_mut(node_a_index)
            .expect("Node A must exist")
            .update_routing_view()
            .await;

        // Allow routing tasks to start
        tokio::time::sleep(Duration::from_millis(crate::testnet::TASK_STARTUP_DELAY_MS)).await;

        let node_a = harness.test_node(node_a_index).expect("Node A");
        let node_b = harness.test_node(node_b_index).expect("Node B");
        let p2p_a = node_a.p2p_node.as_ref().expect("Node A P2P").clone();

        let target_peer_id = node_b
            .p2p_node
            .as_ref()
            .expect("Node B P2P")
            .transport_peer_id()
            .expect("Node B transport peer ID");

        // Store chunk data locally on node A, compute content address
        let content = b"fresh offer e2e test payload";
        let key = compute_address(content);

        // Build FreshOfferRequest with valid (non-empty) PoP
        let request_id: u64 = rand::thread_rng().gen();
        let message = ReplicationMessage {
            request_id,
            body: ReplicationBody::FreshOffer(FreshOfferRequest {
                key,
                content: content.to_vec(),
                proof_of_payment: vec![1, 2, 3],
            }),
        };

        let resp = send_and_await_replication_response(&p2p_a, &target_peer_id, &message)
            .await
            .expect("Should receive replication response");

        // The receiver may accept (if responsible) or reject (if not responsible)
        match resp {
            ReplicationBody::FreshOfferResponse(FreshOfferResponse::Accepted { key: k }) => {
                assert_eq!(k, key, "Accepted key must match request key");
                // Verify chunk is stored on node B via its existing storage
                let b_storage = node_b
                    .ant_protocol
                    .as_ref()
                    .expect("Node B AntProtocol")
                    .storage();
                assert!(
                    b_storage.exists(&key),
                    "Accepted chunk must exist in node B storage"
                );
                // Verify key is in node B's PaidForList
                let paid_list = node_b.paid_list.as_ref().expect("Node B paid_list");
                assert!(
                    paid_list.read().contains(&key),
                    "Accepted key must be in node B's PaidForList"
                );
            }
            ReplicationBody::FreshOfferResponse(FreshOfferResponse::Rejected {
                key: k,
                reason,
            }) => {
                assert_eq!(k, key, "Rejected key must match request key");
                assert!(
                    !reason.is_empty(),
                    "Rejection reason must not be empty, got: {reason}"
                );
            }
            other => panic!("Expected FreshOfferResponse, got: {other:?}"),
        }

        // Test rejection: send FreshOffer with empty PoP (must always be rejected)
        let reject_request_id: u64 = rand::thread_rng().gen();
        let reject_message = ReplicationMessage {
            request_id: reject_request_id,
            body: ReplicationBody::FreshOffer(FreshOfferRequest {
                key,
                content: content.to_vec(),
                proof_of_payment: vec![], // Empty = invalid
            }),
        };

        let reject_resp =
            send_and_await_replication_response(&p2p_a, &target_peer_id, &reject_message)
                .await
                .expect("Should receive rejection response");

        match reject_resp {
            ReplicationBody::FreshOfferResponse(FreshOfferResponse::Rejected {
                reason, ..
            }) => {
                assert!(
                    reason.contains("proof of payment"),
                    "Empty PoP rejection reason should mention proof of payment, got: {reason}"
                );
            }
            other => panic!("Expected Rejected for empty PoP, got: {other:?}"),
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 15. Neighbor-sync session with cross-node topology
    // =========================================================================

    /// Exercise the full neighbor-sync session logic using two live nodes'
    /// real P2P peer IDs and routing tables.
    ///
    /// Not sent over P2P because `SyncHints` dispatch isn't wired in `node.rs`,
    /// but uses real topology from two live nodes, which is significantly more
    /// realistic than existing single-node tests.
    ///
    /// Design doc coverage: Section 6.2 rules 4-9, Section 7.1,
    /// test matrix scenarios 5, 7, 8, 37.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_neighbor_sync_session_cross_node() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node_a = harness.test_node(3).expect("Node 3 should exist");
        let node_b = harness.test_node(4).expect("Node 4 should exist");

        let peers_a = node_a.connected_peers().await;
        let peers_b = node_b.connected_peers().await;
        assert!(
            peers_a.len() >= MIN_PEERS_FOR_HINT_TEST,
            "Node A needs at least {MIN_PEERS_FOR_HINT_TEST} peers"
        );
        assert!(
            peers_b.len() >= MIN_PEERS_FOR_HINT_TEST,
            "Node B needs at least {MIN_PEERS_FOR_HINT_TEST} peers"
        );

        // Build routing tables using production peer_id_to_xor_name (hex decode)
        // Fall back to SHA256 hash for peer IDs that aren't hex-encoded
        let rt_a: Vec<(String, XorName)> = peers_a
            .iter()
            .map(|id| {
                let xor = peer_id_to_xor_name(id).unwrap_or_else(|| compute_address(id.as_bytes()));
                (id.clone(), xor)
            })
            .collect();
        let rt_b: Vec<(String, XorName)> = peers_b
            .iter()
            .map(|id| {
                let xor = peer_id_to_xor_name(id).unwrap_or_else(|| compute_address(id.as_bytes()));
                (id.clone(), xor)
            })
            .collect();

        let id_a = &node_a.node_id;
        let xor_a = peer_id_to_xor_name(id_a).unwrap_or_else(|| compute_address(id_a.as_bytes()));
        let id_b = &node_b.node_id;
        let xor_b = peer_id_to_xor_name(id_b).unwrap_or_else(|| compute_address(id_b.as_bytes()));

        // Store distinct chunks on each node
        let data_a1 = test_data(64, 0xA1);
        let data_a2 = test_data(64, 0xA2);
        let key_a1 = node_a.store_chunk(&data_a1).await.expect("Store A1");
        let key_a2 = node_a.store_chunk(&data_a2).await.expect("Store A2");
        let local_keys_a = vec![key_a1, key_a2];

        let data_b1 = test_data(64, 0xB1);
        let data_b2 = test_data(64, 0xB2);
        let key_b1 = node_b.store_chunk(&data_b1).await.expect("Store B1");
        let key_b2 = node_b.store_chunk(&data_b2).await.expect("Store B2");
        let local_keys_b = vec![key_b1, key_b2];

        // Node A computes hints for B
        let hints_a_for_b = compute_hints_for_peer(
            id_a,
            &xor_a,
            id_b,
            &rt_a,
            &local_keys_a,
            &local_keys_a, // Same keys in paid list for simplicity
        );

        // Cross-set dedup: no key in both replica and paid
        for key in &hints_a_for_b.replica_hints {
            assert!(
                !hints_a_for_b.paid_hints.contains(key),
                "Cross-set dedup violated: key in both replica and paid hints"
            );
        }

        // Node B processes session with A's hints
        let session_b = process_session(
            id_b,
            &xor_b,
            id_a,
            &rt_b,
            &local_keys_b,
            &local_keys_b,
            &hints_a_for_b.replica_hints,
            &hints_a_for_b.paid_hints,
            &|_| false, // nothing is local/pending on B for A's keys
            &|_| false, // nothing in B's paid list for A's keys
        );

        // Verify direction is correct
        let a_in_b_rt = rt_b.iter().any(|(id, _)| id == id_a);
        if a_in_b_rt {
            assert_eq!(
                session_b.direction,
                SessionDirection::Bidirectional,
                "Peer in LocalRT should produce Bidirectional session"
            );
        } else {
            assert_eq!(
                session_b.direction,
                SessionDirection::OutboundOnly,
                "Peer not in LocalRT should produce OutboundOnly session"
            );
            // Outbound-only sessions admit zero keys
            assert!(
                session_b.admitted.is_empty(),
                "OutboundOnly session should admit no keys"
            );
        }

        // Cross-set dedup on admitted keys: no key in both replica and paid
        let replica_admitted: HashSet<XorName> = session_b
            .admitted
            .iter()
            .filter(|a| a.pipeline == HintPipeline::Replica)
            .map(|a| a.key)
            .collect();
        let paid_admitted: HashSet<XorName> = session_b
            .admitted
            .iter()
            .filter(|a| a.pipeline == HintPipeline::PaidOnly)
            .map(|a| a.key)
            .collect();
        assert!(
            replica_admitted.is_disjoint(&paid_admitted),
            "Admitted keys must not appear in both replica and paid pipelines"
        );

        // Bidirectional admitted replica keys pass is_responsible,
        // paid keys pass is_in_paid_close_group
        for admitted in &session_b.admitted {
            match admitted.pipeline {
                HintPipeline::Replica => {
                    assert!(
                        routing::is_responsible(id_b, &xor_b, &admitted.key, &rt_b),
                        "Admitted replica key must pass is_responsible"
                    );
                }
                HintPipeline::PaidOnly => {
                    assert!(
                        routing::is_in_paid_close_group(id_b, &xor_b, &admitted.key, &rt_b),
                        "Admitted paid key must pass is_in_paid_close_group"
                    );
                }
            }
        }

        // Reverse direction: B computes hints for A, A processes session
        let hints_b_for_a =
            compute_hints_for_peer(id_b, &xor_b, id_a, &rt_b, &local_keys_b, &local_keys_b);

        let session_a = process_session(
            id_a,
            &xor_a,
            id_b,
            &rt_a,
            &local_keys_a,
            &local_keys_a,
            &hints_b_for_a.replica_hints,
            &hints_b_for_a.paid_hints,
            &|_| false,
            &|_| false,
        );

        // Same direction invariants
        let b_in_a_rt = rt_a.iter().any(|(id, _)| id == id_b);
        if b_in_a_rt {
            assert_eq!(session_a.direction, SessionDirection::Bidirectional);
        } else {
            assert_eq!(session_a.direction, SessionDirection::OutboundOnly);
            assert!(session_a.admitted.is_empty());
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // 16. Audit challenge-response over P2P
    // =========================================================================

    /// Send an `AuditChallenge` to a node that holds chunks and verify
    /// the digest response matches local recomputation.
    ///
    /// Design doc coverage: Section 15 steps 1-10,
    /// test matrix scenarios 19, 53, 54, 55.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_audit_challenge_response_over_p2p() {
        let mut harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let node_a_index = 3;
        let node_b_index = 4;

        // Enable replication routing on node B (the audit target)
        harness
            .network_mut()
            .node_mut(node_b_index)
            .expect("Node B must exist")
            .enable_replication_routing();

        // Allow routing task to start
        tokio::time::sleep(Duration::from_millis(crate::testnet::TASK_STARTUP_DELAY_MS)).await;

        let node_a = harness.test_node(node_a_index).expect("Node A");
        let node_b = harness.test_node(node_b_index).expect("Node B");
        let p2p_a = node_a.p2p_node.as_ref().expect("Node A P2P").clone();

        let target_peer_id = node_b
            .p2p_node
            .as_ref()
            .expect("Node B P2P")
            .transport_peer_id()
            .expect("Node B transport peer ID");

        // Store 3 known chunks on node B's local storage
        let chunk_count: usize = 3;
        let mut stored_keys = Vec::with_capacity(chunk_count);
        let mut stored_content: HashMap<XorName, Vec<u8>> = HashMap::new();

        for seed in 0..chunk_count {
            #[allow(clippy::cast_possible_truncation)]
            let data = test_data(128, 0xC0 + seed as u8);
            let key = node_b.store_chunk(&data).await.expect("Store chunk on B");
            stored_keys.push(key);
            stored_content.insert(key, data);
        }

        // Create an absent key (never stored)
        let absent_key = compute_address(b"this chunk does not exist on node B");
        assert!(
            !stored_keys.contains(&absent_key),
            "Absent key must not collide with stored keys"
        );

        // Construct AuditChallengeRequest: 3 present + 1 absent = 4 keys
        let nonce: [u8; 32] = rand::thread_rng().gen();
        let challenge_id: u64 = rand::thread_rng().gen();
        let challenge_keys_count: usize = 4;
        let mut challenge_keys = stored_keys.clone();
        challenge_keys.push(absent_key);
        assert_eq!(challenge_keys.len(), challenge_keys_count);

        let request_id: u64 = rand::thread_rng().gen();
        let message = ReplicationMessage {
            request_id,
            body: ReplicationBody::AuditChallenge(AuditChallengeRequest {
                challenge_id,
                nonce,
                keys: challenge_keys.clone(),
            }),
        };

        let resp = send_and_await_replication_response(&p2p_a, &target_peer_id, &message)
            .await
            .expect("Should receive audit response");

        // Assert response is Digests with correct challenge_id
        let digests = match resp {
            ReplicationBody::AuditResponse(AuditChallengeResponse::Digests {
                challenge_id: cid,
                digests,
            }) => {
                assert_eq!(cid, challenge_id, "Challenge ID must be echoed in response");
                digests
            }
            other => panic!("Expected AuditResponse::Digests, got: {other:?}"),
        };

        // Assert digest count matches key count
        assert_eq!(
            digests.len(),
            challenge_keys_count,
            "Digest count must match challenge key count"
        );

        // Verify using verify_audit_response: 3 Passed, 1 Absent
        let results = verify_audit_response(
            &nonce,
            &target_peer_id,
            &challenge_keys,
            &digests,
            &stored_content,
        )
        .expect("Audit response should have matching lengths");

        // First 3 keys are present on B and we have local copies → Passed
        for (i, result) in results.iter().enumerate().take(chunk_count) {
            assert_eq!(
                *result,
                AuditKeyResult::Passed,
                "Key {i} should pass audit verification"
            );
        }

        // Last key is absent on B → Absent
        assert_eq!(
            results[chunk_count],
            AuditKeyResult::Absent,
            "Absent key should return Absent result"
        );

        // Assert absent key returned ABSENT_DIGEST
        assert_eq!(
            digests[chunk_count], ABSENT_DIGEST,
            "Absent key digest must be ABSENT_DIGEST ([0u8; 32])"
        );

        // Manually recompute one digest and verify it matches
        let verify_key = &challenge_keys[0];
        let verify_content = stored_content.get(verify_key).expect("Content for key 0");
        let expected_digest =
            compute_audit_digest(&nonce, &target_peer_id, verify_key, verify_content);
        assert_eq!(
            digests[0], expected_digest,
            "Manually recomputed digest must match network response"
        );

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }
}
