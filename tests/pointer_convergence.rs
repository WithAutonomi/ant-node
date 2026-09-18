//! Convergence and payment-binding properties of the pointer merge rule.
//!
//! ADR-0015's claim is that selecting the maximum over a total order on
//! *states* is idempotent, commutative and associative, so every node reaches
//! the same value from any delivery interleaving given the same record set.
//! These are the property tests behind that claim, plus the two anti-abuse
//! properties the merge rule exists to provide: one payment funds one state,
//! and no re-signature of a stored state can displace it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use ant_protocol::pointer::{Pointer, PointerTarget, PointerTargetKind};
use proptest::prelude::*;
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};

/// A deterministic keypair, so a failing case is reproducible from its seed.
fn keypair(seed: u8) -> (MlDsaPublicKey, MlDsaSecretKey) {
    ml_dsa_65().generate_keypair_from_seed(&[seed; 32])
}

fn signed(seed: u8, counter: u64, target_byte: u8, kind: PointerTargetKind) -> Pointer {
    let (pk, sk) = keypair(seed);
    let target = PointerTarget::new(kind, [target_byte; 32]);
    Pointer::sign(&sk, &pk, counter, target).expect("signing a pointer")
}

/// Fold a delivery order down to the winner, as a node's store does.
fn winner<'a>(order: &[&'a Pointer]) -> &'a Pointer {
    let mut best = order.first().copied().expect("non-empty delivery");
    for candidate in order.iter().skip(1) {
        if candidate.replaces(best) {
            best = candidate;
        }
    }
    best
}

/// Visit every permutation of `order`, calling `check` on each.
fn permute(
    order: &mut Vec<&Pointer>,
    start: usize,
    check: &mut impl FnMut(&[&Pointer]) -> Result<(), TestCaseError>,
    seen: &mut usize,
) -> Result<(), TestCaseError> {
    if start == order.len() {
        *seen += 1;
        return check(order);
    }
    for i in start..order.len() {
        order.swap(start, i);
        permute(order, start + 1, check, seen)?;
        order.swap(start, i);
    }
    Ok(())
}

/// `n!`, for asserting that every permutation really was visited.
fn factorial(n: usize) -> usize {
    (1..=n).product()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// Any permutation of a record set reaches the same state.
    #[test]
    fn every_delivery_order_converges(
        counters in prop::collection::vec(0u64..4, 2..6),
        targets in prop::collection::vec(0u8..4, 2..6),
    ) {
        let len = counters.len().min(targets.len());
        let records: Vec<Pointer> = (0..len)
            .map(|i| {
                let counter = counters.get(i).copied().unwrap_or(0);
                let target = targets.get(i).copied().unwrap_or(0);
                signed(1, counter, target, PointerTargetKind::Chunk)
            })
            .collect();

        let forward: Vec<&Pointer> = records.iter().collect();
        let expected = winner(&forward).state_id();

        // Every permutation, not a sample of them: the sets are small enough
        // that "any delivery order" can be checked exhaustively.
        let mut order: Vec<&Pointer> = records.iter().collect();
        let mut permutations = 0usize;
        permute(&mut order, 0, &mut |candidate| {
            prop_assert_eq!(winner(candidate).state_id(), expected);
            Ok(())
        }, &mut permutations)?;
        prop_assert_eq!(permutations, factorial(records.len()));
    }

    /// Delivering a record twice changes nothing: the fold is idempotent.
    #[test]
    fn duplicate_delivery_changes_nothing(
        counter in 0u64..8,
        target in 0u8..8,
        extra_counter in 0u64..8,
        extra_target in 0u8..8,
    ) {
        let first = signed(1, counter, target, PointerTargetKind::Chunk);
        let second = signed(1, extra_counter, extra_target, PointerTargetKind::Chunk);

        let once = winner(&[&first, &second]).state_id();
        let twice = winner(&[&first, &second, &first, &second]).state_id();
        let thrice = winner(&[&second, &first, &second, &first, &first]).state_id();
        prop_assert_eq!(once, twice);
        prop_assert_eq!(once, thrice);
    }

    /// Exactly one of `a replaces b` / `b replaces a` holds for distinct states,
    /// and neither holds for equal ones. Without this two nodes could disagree.
    #[test]
    fn the_comparator_is_antisymmetric(
        left_counter in 0u64..4,
        left_target in 0u8..4,
        right_counter in 0u64..4,
        right_target in 0u8..4,
    ) {
        let left = signed(1, left_counter, left_target, PointerTargetKind::Chunk);
        let right = signed(1, right_counter, right_target, PointerTargetKind::Chunk);

        if left.state_id() == right.state_id() {
            prop_assert!(!left.replaces(&right));
            prop_assert!(!right.replaces(&left));
        } else {
            prop_assert_ne!(left.replaces(&right), right.replaces(&left));
        }
    }

    /// No number of re-signatures of one state can displace it, and all of them
    /// pay under a single identifier.
    #[test]
    fn re_signing_one_state_neither_wins_nor_pays_again(
        counter in 0u64..64,
        target in 0u8..64,
        variants in 2usize..12,
    ) {
        let records: Vec<Pointer> = (0..variants)
            .map(|_| signed(1, counter, target, PointerTargetKind::Chunk))
            .collect();

        let encodings: BTreeSet<Vec<u8>> = records.iter().map(Pointer::to_bytes).collect();
        prop_assert_eq!(encodings.len(), variants, "ML-DSA signing is randomized");

        let states: BTreeSet<_> = records.iter().map(Pointer::state_id).collect();
        prop_assert_eq!(states.len(), 1, "one state, so one paid identifier");

        for a in &records {
            for b in &records {
                prop_assert!(!a.replaces(b));
            }
        }
    }

    /// A change to any signed field changes the paid identifier, so a receipt
    /// bought for one update cannot fund another. (`state_id` is a 256-bit hash
    /// over a 1,994-byte body, so this is collision resistance, not injectivity;
    /// what is testable is that each field actually reaches the hash.)
    #[test]
    fn every_signed_field_changes_the_paid_identifier(
        counter in 0u64..u64::MAX,
        tag in any::<u8>(),
        target in any::<[u8; 32]>(),
    ) {
        let (pk, sk) = keypair(1);
        let base = Pointer::sign(&sk, &pk, counter, PointerTarget::from_raw_tag(tag, target))
            .expect("sign");

        let other_counter = Pointer::sign(
            &sk, &pk, counter.wrapping_add(1), PointerTarget::from_raw_tag(tag, target),
        ).expect("sign");
        let other_tag = Pointer::sign(
            &sk, &pk, counter, PointerTarget::from_raw_tag(tag.wrapping_add(1), target),
        ).expect("sign");
        let mut flipped = target;
        flipped[0] ^= 1;
        let other_target = Pointer::sign(
            &sk, &pk, counter, PointerTarget::from_raw_tag(tag, flipped),
        ).expect("sign");
        let (other_pk, other_sk) = keypair(2);
        let other_owner = Pointer::sign(
            &other_sk, &other_pk, counter, PointerTarget::from_raw_tag(tag, target),
        ).expect("sign");

        let ids: BTreeSet<_> = [&base, &other_counter, &other_tag, &other_target, &other_owner]
            .iter()
            .map(|record| record.state_id())
            .collect();
        prop_assert_eq!(ids.len(), 5, "counter, tag, target and owner all reach state_id");
    }

    /// Every record of one owner lives at one address, whatever it says —
    /// including under a target tag this build does not know.
    #[test]
    fn the_address_tracks_only_the_owner(
        counter in 0u64..1000,
        tag in any::<u8>(),
        target_bytes in any::<[u8; 32]>(),
    ) {
        let (pk, sk) = keypair(3);
        let target = PointerTarget::from_raw_tag(tag, target_bytes);
        let record = Pointer::sign(&sk, &pk, counter, target).expect("sign");
        let reference = signed(3, 0, 0, PointerTargetKind::Chunk);
        prop_assert_eq!(record.address(), reference.address());
        prop_assert_ne!(record.address(), signed(4, 0, 0, PointerTargetKind::Chunk).address());

        // An unknown tag round-trips untouched; the node never interprets it.
        let parsed = Pointer::from_bytes(&record.to_bytes()).expect("parse");
        prop_assert_eq!(parsed.target().kind_tag(), tag);
        prop_assert_eq!(parsed.target().address, target_bytes);
    }

    /// The merge order holds over arbitrary target bytes, not just the
    /// repeated-byte targets the other cases use.
    #[test]
    fn arbitrary_targets_order_by_their_bytes(
        counter in 0u64..4,
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>(),
        tag in any::<u8>(),
    ) {
        let (pk, sk) = keypair(6);
        let a = Pointer::sign(&sk, &pk, counter, PointerTarget::from_raw_tag(tag, left))
            .expect("sign");
        let b = Pointer::sign(&sk, &pk, counter, PointerTarget::from_raw_tag(tag, right))
            .expect("sign");

        match left.cmp(&right) {
            std::cmp::Ordering::Less => {
                prop_assert!(a.replaces(&b), "smaller target bytes win");
                prop_assert!(!b.replaces(&a));
            }
            std::cmp::Ordering::Greater => {
                prop_assert!(b.replaces(&a));
                prop_assert!(!a.replaces(&b));
            }
            std::cmp::Ordering::Equal => {
                prop_assert!(!a.replaces(&b));
                prop_assert!(!b.replaces(&a));
            }
        }
    }

    /// Any record that parses is correctly signed; any mutation of its bytes
    /// either fails to parse or fails to verify. Nothing forged gets through.
    #[test]
    fn no_mutation_of_a_record_survives_validation(
        index in 0usize..5303,
        mask in 1u8..255,
    ) {
        let record = signed(5, 11, 22, PointerTargetKind::Chunk);
        let mut bytes = record.to_bytes();
        let Some(byte) = bytes.get_mut(index) else {
            return Ok(());
        };
        *byte ^= mask;

        match Pointer::from_bytes(&bytes) {
            Err(_) => {}
            Ok(parsed) => {
                // The only mutations that can verify are ones that produced a
                // different but still-valid signature encoding of the same
                // body, which cannot happen for a single flipped byte. If one
                // ever does, it must still be the same state.
                prop_assert_eq!(parsed.state_id(), record.state_id());
            }
        }
    }
}

/// A worked instance of the attack the merge rule exists to stop: 64 valid
/// signatures over one paid state, submitted worst-first.
#[test]
fn sixty_four_signatures_over_one_state_yield_one_winner() {
    let records: Vec<Pointer> = (0..64)
        .map(|_| signed(7, 9, 9, PointerTargetKind::Chunk))
        .collect();

    let encodings: BTreeSet<Vec<u8>> = records.iter().map(Pointer::to_bytes).collect();
    assert_eq!(encodings.len(), 64, "64 distinct valid encodings");

    let states: BTreeSet<_> = records.iter().map(Pointer::state_id).collect();
    assert_eq!(states.len(), 1, "all 64 sit at one paid identifier");

    // Sorted worst-first is the submission order that would have made every
    // record win under a byte-ordering tie-break.
    let mut sorted: Vec<&Pointer> = records.iter().collect();
    sorted.sort_by_key(|record| record.to_bytes());

    let first = sorted.first().copied().expect("non-empty");
    for candidate in &sorted {
        assert!(
            !candidate.replaces(first),
            "no re-signature of a stored state may displace it"
        );
    }
    assert_eq!(winner(&sorted).state_id(), first.state_id());
}

/// Golden vectors pinning the wire format.
///
/// Field offsets, the big-endian counter, the inclusion of every owner byte and
/// all 33 target bytes, and the two domain separators are consensus: a node that
/// disagrees about any of them computes a different address or a different paid
/// identifier and silently partitions. These assertions restate the format
/// independently of the code under test, so a refactor that changes it fails
/// here rather than in production.
#[test]
fn the_wire_format_is_what_the_adr_says() {
    use blake3::Hasher;

    let (pk, sk) = keypair(42);
    let target_address = [0xABu8; 32];
    let counter = 0x0102_0304_0506_0708u64;
    let record = Pointer::sign(
        &sk,
        &pk,
        counter,
        PointerTarget::from_raw_tag(0x5A, target_address),
    )
    .expect("sign");
    let bytes = record.to_bytes();

    // Layout.
    assert_eq!(bytes.len(), 5303, "1 + 1952 + 8 + 33 + 3309");
    assert_eq!(bytes.first().copied(), Some(1u8), "format_version is 1");
    assert_eq!(
        bytes.get(1..1953).expect("owner range"),
        pk.to_bytes().as_slice(),
        "every owner byte is carried verbatim at offset 1"
    );
    assert_eq!(
        bytes.get(1953..1961).expect("counter range"),
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        "the counter is big-endian at offset 1953"
    );
    assert_eq!(
        bytes.get(1961).copied(),
        Some(0x5A),
        "the target tag sits at offset 1961, uninterpreted"
    );
    assert_eq!(
        bytes.get(1962..1994).expect("target range"),
        target_address.as_slice(),
        "all 32 target address bytes follow the tag"
    );

    // Fixed expected values for the fixed seed. These are consensus: a build
    // that computes anything else partitions from the network, so they are
    // written out rather than recomputed from the code under test.
    assert_eq!(
        hex::encode(record.address()),
        "f82d07b1e8be4b9bc9b87df513baf57f65478ff321e4ecb5a0883f9bf8f594b7",
        "the pointer address for seed 42"
    );
    assert_eq!(
        hex::encode(record.state_id()),
        "36684c7d59d7f5ac2aeef581377fcbf8d88689fda0c01ead2fde66d7a8120aea",
        "the paid state identifier for this record"
    );

    // And the derivations those constants come from, restated independently.
    let mut address_hasher = Hasher::new();
    address_hasher.update(b"autonomi.pointer.address.v1");
    address_hasher.update(&pk.to_bytes());
    assert_eq!(
        record.address(),
        *address_hasher.finalize().as_bytes(),
        "the address derives from the owner key alone"
    );

    let mut state_hasher = Hasher::new();
    state_hasher.update(b"autonomi.pointer.state.v1");
    state_hasher.update(bytes.get(..1994).expect("body range"));
    assert_eq!(
        record.state_id(),
        *state_hasher.finalize().as_bytes(),
        "state_id covers the whole body and nothing else"
    );

    // The signature verifies over the body under the literal context, and does
    // not verify under a different one. The context is consensus too.
    let dsa = ml_dsa_65();
    let signature = MlDsaSignature::from_bytes(
        MlDsaVariant::MlDsa65,
        bytes.get(1994..).expect("signature range"),
    )
    .expect("signature parses");
    assert!(
        dsa.verify_with_context(
            &pk,
            bytes.get(..1994).expect("body range"),
            &signature,
            b"autonomi.pointer.head.v1",
        )
        .expect("verify"),
        "the signature is over the body under autonomi.pointer.head.v1"
    );
    assert!(
        !dsa.verify_with_context(
            &pk,
            bytes.get(..1994).expect("body range"),
            &signature,
            b"autonomi.pointer.head.v2",
        )
        .expect("verify"),
        "and not under any other context"
    );

    // The domains are distinct, so neither identifier can be mistaken for the
    // other or for a plain content address.
    assert_ne!(record.address(), record.state_id());
    assert_ne!(
        record.address(),
        *blake3::hash(&pk.to_bytes()).as_bytes(),
        "the address is domain-separated from a bare hash of the key"
    );
}

/// The same attack, driven through a real store: 64 valid signatures over one
/// paid state must produce exactly one file and never rewrite it.
///
/// The fold above proves the comparator refuses them; this proves the storage
/// layer does, which is where the cost would actually have been paid.
#[tokio::test]
async fn sixty_four_signatures_buy_exactly_one_write() {
    use ant_node::pointer::store::{PointerStore, PutOutcome};

    let dir = tempfile::tempdir().expect("tempdir");
    let store = PointerStore::new(dir.path()).await.expect("open store");

    let first = signed(7, 9, 9, PointerTargetKind::Chunk);
    assert_eq!(
        store.put_bytes(&first.to_bytes()).await.expect("put"),
        PutOutcome::Changed
    );

    let path = store.dir().join(hex::encode(first.address()));
    let stored = std::fs::read(&path).expect("read back");

    for _ in 0..63 {
        let variant = signed(7, 9, 9, PointerTargetKind::Chunk);
        assert_ne!(
            variant.to_bytes(),
            first.to_bytes(),
            "signing is randomized"
        );
        assert_eq!(
            store.put_bytes(&variant.to_bytes()).await.expect("put"),
            PutOutcome::Unchanged
        );
    }

    assert_eq!(
        std::fs::read(&path).expect("read back"),
        stored,
        "63 re-signatures after the first must not touch the stored bytes"
    );
    assert_eq!(store.len(), 1, "one address, one record");

    let files: Vec<_> = std::fs::read_dir(store.dir())
        .expect("read dir")
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    assert_eq!(files.len(), 1, "one payment bought one file: {files:?}");
}

// =============================================================================
// Version and counter gaps
// =============================================================================

/// A version-only change must not reuse a paid state identifier.
///
/// `format_version` is the first byte of the signed body and `state_id` hashes
/// the whole body, so a record differing only in its version is a different
/// state. Without this a future format could spend a receipt bought for
/// version 1 — the free-update defect, reintroduced through the version field.
#[test]
fn a_version_only_change_cannot_reuse_a_paid_state_identifier() {
    use ant_protocol::pointer::{state_id_for_body, POINTER_BODY_LEN, POINTER_FORMAT_VERSION};

    let record = signed(11, 9, 9, PointerTargetKind::Chunk);
    let mut body = record
        .to_bytes()
        .get(..POINTER_BODY_LEN)
        .expect("body")
        .to_vec();

    let paid = state_id_for_body(&body);
    assert_eq!(
        paid,
        record.state_id(),
        "the baseline is the record's own id"
    );

    let mut seen = BTreeSet::new();
    seen.insert(paid);
    for version in 0u8..=u8::MAX {
        if version == POINTER_FORMAT_VERSION {
            continue;
        }
        if let Some(byte) = body.first_mut() {
            *byte = version;
        }
        let other = state_id_for_body(&body);
        assert_ne!(
            other, paid,
            "version {version} must not share version {POINTER_FORMAT_VERSION}'s paid id"
        );
        assert!(
            seen.insert(other),
            "version {version} collided with another version's paid id"
        );
    }
    assert_eq!(seen.len(), 256, "every version has its own paid identifier");
}

/// A record of an unknown version is refused outright, so it can never be
/// stored under version 1's authority even if someone paid for it.
#[test]
fn an_unknown_version_is_refused_rather_than_accepted_at_its_own_price() {
    use ant_protocol::pointer::{PointerError, PointerState, POINTER_FORMAT_VERSION};

    let record = signed(12, 1, 1, PointerTargetKind::Chunk);
    for version in [0u8, 2, 7, u8::MAX] {
        assert_ne!(version, POINTER_FORMAT_VERSION);
        let mut bytes = record.to_bytes();
        if let Some(byte) = bytes.first_mut() {
            *byte = version;
        }
        assert!(matches!(
            Pointer::from_bytes(&bytes),
            Err(PointerError::UnknownFormatVersion(v)) if v == version
        ));
        assert!(matches!(
            PointerState::parse(&bytes),
            Err(PointerError::UnknownFormatVersion(v)) if v == version
        ));
    }
}

/// At `u64::MAX` no *counter* can out-rank the winner, but a smaller *target*
/// still can. That asymmetry is why migration has to happen before the terminal
/// update rather than on it.
#[test]
fn a_terminal_counter_cannot_be_out_counted_only_out_targeted() {
    let terminal = signed(13, u64::MAX, 5, PointerTargetKind::Chunk);
    assert!(terminal.is_terminal());
    assert!(terminal.next_counter().is_err(), "no successor exists");

    // Nothing at any lower counter replaces it.
    for counter in [0u64, 1, 1000, u64::MAX - 2, u64::MAX - 1] {
        let earlier = signed(13, counter, 0, PointerTargetKind::Chunk);
        assert!(!earlier.replaces(&terminal));
        assert!(terminal.replaces(&earlier));
    }

    // The order does not degenerate there: equal-counter conflicts at the
    // maximum still resolve deterministically, so replicas cannot split.
    let low = signed(13, u64::MAX, 1, PointerTargetKind::Chunk);
    let high = signed(13, u64::MAX, 2, PointerTargetKind::Chunk);
    assert!(low.replaces(&high));
    assert!(!high.replaces(&low));
    assert_eq!(winner(&[&high, &low]).state_id(), low.state_id());
    assert_eq!(winner(&[&low, &high]).state_id(), low.state_id());
}

/// Why migration must happen *before* the terminal update.
///
/// At `u64::MAX` the counter can no longer advance, but the pointer is not
/// frozen: the merge order still resolves equal counters by target bytes, and
/// *smaller* target bytes win. So a migration written at the terminal counter
/// can still be displaced — by the owner, or by anyone replaying an older
/// signed record of theirs with a smaller target. The only safe migration is
/// one made while a successor counter still exists, because a strictly larger
/// counter is the one move nothing can answer.
#[tokio::test]
async fn migration_must_happen_before_the_terminal_update() {
    use ant_node::pointer::store::{PointerStore, PutOutcome};
    use ant_protocol::pointer::PointerTarget;
    use saorsa_pqc::api::sig::ml_dsa_65;

    let dir = tempfile::tempdir().expect("tempdir");
    let store = PointerStore::new(dir.path()).await.expect("store");

    let (pk, sk) = ml_dsa_65().generate_keypair_from_seed(&[14u8; 32]);
    let sign_at = |counter: u64, target: PointerTarget| {
        Pointer::sign(&sk, &pk, counter, target).expect("sign")
    };

    // One update short of the end: a successor counter still exists.
    let penultimate = sign_at(
        u64::MAX - 1,
        PointerTarget::new(PointerTargetKind::Chunk, [0x10u8; 32]),
    );
    assert!(!penultimate.is_terminal());
    assert_eq!(
        store.put_bytes(&penultimate.to_bytes()).await.expect("put"),
        PutOutcome::Changed
    );

    // The safe migration: spend the last counter. A strictly larger counter
    // beats every target, so nothing at u64::MAX - 1 can answer it.
    let migration = sign_at(
        penultimate.next_counter().expect("successor exists"),
        PointerTarget::new(PointerTargetKind::Pointer, [0x80u8; 32]),
    );
    assert_eq!(
        store.put_bytes(&migration.to_bytes()).await.expect("put"),
        PutOutcome::Changed
    );
    assert!(migration.is_terminal());
    assert!(migration.next_counter().is_err());

    // Now the danger. The counter is spent, so the only remaining moves are to
    // strictly smaller target bytes — and they still win.
    let smaller_target = sign_at(
        u64::MAX,
        PointerTarget::new(PointerTargetKind::Chunk, [0x01u8; 32]),
    );
    assert!(
        smaller_target.to_bytes() != migration.to_bytes(),
        "a genuinely different state"
    );
    assert_eq!(
        store
            .put_bytes(&smaller_target.to_bytes())
            .await
            .expect("put"),
        PutOutcome::Changed,
        "a terminal pointer is NOT frozen: a smaller target still displaces it"
    );

    // Larger target bytes cannot claw it back: the move is one-way.
    assert_eq!(
        store.put_bytes(&migration.to_bytes()).await.expect("put"),
        PutOutcome::Stale,
        "and the displaced migration can never be restored"
    );

    // Which is the whole point: a migration made at the terminal counter is
    // not final, so it has to be made earlier, where the counter still answers.
    assert!(smaller_target.replaces(&migration));
    assert!(!migration.replaces(&smaller_target));
}
