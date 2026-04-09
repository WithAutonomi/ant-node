//! Transport trust model tests (TOFU, rotations, channel binding, token binding)
//!
//! These tests define the expected behavior and public surface for the upcoming
//! transport trust work. They are added before implementation (TDD) and will
//! initially fail to compile until the corresponding modules are introduced.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_transport as quic;
use saorsa_transport::crypto::raw_public_keys::pqc::{
    create_subject_public_key_info, generate_ml_dsa_keypair,
};

use tempfile::TempDir;

// Helper: compute SPKI fingerprint (BLAKE3 hash) from SPKI bytes
fn spki_fingerprint(spki: &[u8]) -> [u8; 32] {
    *blake3::hash(spki).as_bytes()
}

#[test]
fn tofu_first_contact_pins_and_emits_event() {
    // Arrange: temp FS PinStore and an event collector policy
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());

    let events = std::sync::Arc::new(quic::trust::EventCollector::default());
    let policy = quic::trust::TransportPolicy::default()
        .with_allow_tofu(true)
        .with_require_continuity(true)
        .with_event_sink(events.clone());

    // Peer SPKI (ML-DSA-65)
    let (pk, _sk) = generate_ml_dsa_keypair().unwrap();
    let spki = create_subject_public_key_info(&pk).unwrap();
    let fpr = spki_fingerprint(&spki);

    // Act: first seen
    quic::trust::register_first_seen(&pinstore, &policy, &spki).expect("TOFU should accept");

    // Assert: pin persisted and event emitted
    let rec = pinstore.load(&fpr).expect("load ok").expect("present");
    assert_eq!(rec.current_fingerprint, fpr);
    assert!(events.first_seen_called_with(&fpr, &fpr));
}

#[test]
fn rotation_with_continuity_is_accepted() {
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());
    let policy = quic::trust::TransportPolicy::default().with_require_continuity(true);

    // Old key (ML-DSA-65)
    let (old_pk, old_sk) = generate_ml_dsa_keypair().unwrap();
    let old_spki = create_subject_public_key_info(&old_pk).unwrap();
    let old_fpr = spki_fingerprint(&old_spki);
    quic::trust::register_first_seen(&pinstore, &policy, &old_spki).unwrap();

    // New key + continuity signature by old key over new SPKI fingerprint
    let (new_pk, _new_sk) = generate_ml_dsa_keypair().unwrap();
    let new_spki = create_subject_public_key_info(&new_pk).unwrap();
    let new_fpr = spki_fingerprint(&new_spki);

    let continuity_sig = quic::trust::sign_continuity(&old_sk, &new_fpr);

    quic::trust::register_rotation(&pinstore, &policy, &old_fpr, &new_spki, &continuity_sig)
        .expect("rotation accepted");

    let rec = pinstore.load(&old_fpr).unwrap().unwrap();
    assert_eq!(rec.current_fingerprint, new_fpr);
    assert_eq!(rec.previous_fingerprint, Some(old_fpr));
}

#[test]
fn rotation_without_continuity_is_rejected() {
    let dir = TempDir::new().unwrap();
    let pinstore = quic::trust::FsPinStore::new(dir.path());
    let policy = quic::trust::TransportPolicy::default().with_require_continuity(true);

    // Old key (ML-DSA-65)
    let (old_pk, _old_sk) = generate_ml_dsa_keypair().unwrap();
    let old_spki = create_subject_public_key_info(&old_pk).unwrap();
    let old_fpr = spki_fingerprint(&old_spki);
    quic::trust::register_first_seen(&pinstore, &policy, &old_spki).unwrap();

    // New key, but no continuity signature provided
    let (new_pk, _new_sk) = generate_ml_dsa_keypair().unwrap();
    let new_spki = create_subject_public_key_info(&new_pk).unwrap();

    let err = quic::trust::register_rotation(&pinstore, &policy, &old_fpr, &new_spki, &[]) // empty sig
        .expect_err("rotation must be rejected without continuity");
    let _ = err; // documented error type TBD
}

#[test]
fn channel_binding_verifies_and_emits_event() {
    // Trust policy & events
    let events = std::sync::Arc::new(quic::trust::EventCollector::default());
    let policy = quic::trust::TransportPolicy::default()
        .with_enable_channel_binding(true)
        .with_event_sink(events.clone());

    // Exporter bytes (pretend derived via TLS exporter)
    let exporter = [42u8; 32];
    quic::trust::perform_channel_binding_from_exporter(&exporter, &policy).expect("ok");
    assert!(events.binding_verified_called());
}

#[test]
fn token_binding_uses_fingerprint_cid_nonce() {
    // Arrange: fake fingerprint and CID
    let fingerprint: [u8; 32] = [7u8; 32];
    let cid = quic::shared::ConnectionId::from_bytes(&[9u8; quic::MAX_CID_SIZE]);

    // Key and nonce
    let mut rng = rand::thread_rng();
    let token_key = quic::token_v2::test_key_from_rng(&mut rng);

    // Act: encode
    let token = quic::token_v2::encode_binding_token(&token_key, &fingerprint, &cid).unwrap();

    // Assert: decode and verify binding
    let decoded = quic::token_v2::decode_binding_token(&token_key, &token).expect("decodes");
    assert_eq!(decoded.spki_fingerprint, fingerprint);
    assert_eq!(decoded.cid, cid);
}
