//! Server-side validation tests for token_v2 semantics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_transport::shared::ConnectionId;

#[test]
fn server_accepts_matching_peer_and_cid() {
    let mut rng = rand::thread_rng();
    let key = saorsa_transport::token_v2::test_key_from_rng(&mut rng);
    let fingerprint: [u8; 32] = [1u8; 32];
    let cid = ConnectionId::new(&[7u8; 8]);

    let tok = saorsa_transport::token_v2::encode_binding_token(&key, &fingerprint, &cid).unwrap();
    assert!(saorsa_transport::token_v2::validate_binding_token(
        &key,
        &tok,
        &fingerprint,
        &cid
    ));
}

#[test]
fn server_rejects_mismatch_peer() {
    let mut rng = rand::thread_rng();
    let key = saorsa_transport::token_v2::test_key_from_rng(&mut rng);
    let fingerprint_ok: [u8; 32] = [2u8; 32];
    let fingerprint_bad: [u8; 32] = [3u8; 32];
    let cid = ConnectionId::new(&[9u8; 8]);
    let tok =
        saorsa_transport::token_v2::encode_binding_token(&key, &fingerprint_ok, &cid).unwrap();
    assert!(!saorsa_transport::token_v2::validate_binding_token(
        &key,
        &tok,
        &fingerprint_bad,
        &cid
    ));
}

#[test]
fn server_rejects_mismatch_cid() {
    let mut rng = rand::thread_rng();
    let key = saorsa_transport::token_v2::test_key_from_rng(&mut rng);
    let fingerprint: [u8; 32] = [4u8; 32];
    let cid_ok = ConnectionId::new(&[5u8; 8]);
    let cid_bad = ConnectionId::new(&[6u8; 8]);
    let tok =
        saorsa_transport::token_v2::encode_binding_token(&key, &fingerprint, &cid_ok).unwrap();
    assert!(!saorsa_transport::token_v2::validate_binding_token(
        &key,
        &tok,
        &fingerprint,
        &cid_bad
    ));
}
