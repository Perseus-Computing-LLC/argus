//! Regression tests for the remediation series; each stage appends the tests for its finding.
#![allow(unused_mut)] // stages before F12 still take `&mut self` in `append`
#[allow(unused_imports)]
use super::*;

fn ledger_with(n: usize) -> InMemoryLedger {
    let mut ledger = InMemoryLedger::new();
    for i in 0..n {
        ledger
            .append("tool.exec", "worker_1", &format!("{{\"step\":{i}}}"))
            .unwrap();
    }
    ledger
}

/// Storage-level forger: recompute every link with the public hash function.
fn relink(events: &mut [AuditEvent]) {
    let mut prev = GENESIS_PREV_HASH.to_string();
    for ev in events.iter_mut() {
        ev.prev_hash = prev;
        ev.event_hash = compute_event_hash(
            ev.sequence,
            &ev.event_id,
            &ev.timestamp,
            &ev.event_type,
            &ev.actor,
            &ev.prev_hash,
            &ev.payload,
        );
        prev = ev.event_hash.clone();
    }
}

fn anchored_at_head(ledger: &InMemoryLedger) -> VerificationPolicy {
    VerificationPolicy {
        anchor: Some(ledger.head().unwrap().unwrap().anchor()),
        ..Default::default()
    }
}

#[test]
fn f1_anchor_rejects_rollback_truncation_and_recomputed_history() {
    let mut ledger = ledger_with(3);
    let policy = anchored_at_head(&ledger);
    let honest = ledger.all_events().unwrap();
    assert!(ledger.verify_chain_with(&policy).unwrap().valid);
    assert!(
        !policy.verify(&honest[..2]).unwrap().valid,
        "tail truncation"
    );
    assert!(
        !policy.verify(&honest[..0]).unwrap().valid,
        "rollback to empty"
    );
    let mut forged = honest.clone();
    forged[0].payload = "{\"step\":\"forged\"}".into();
    relink(&mut forged);
    assert!(
        VerificationPolicy::default().verify(&forged).unwrap().valid,
        "self-consistent"
    );
    assert!(
        !policy.verify(&forged).unwrap().valid,
        "but not the witnessed chain"
    );
    ledger.append("tool.exec", "worker_1", "{}").unwrap();
    assert!(
        ledger.verify_chain_with(&policy).unwrap().valid,
        "growth past the anchor"
    );
}

#[test]
fn f2_field_boundaries_are_bound_into_the_hash() {
    let p = GENESIS_PREV_HASH;
    assert_ne!(
        compute_event_hash(
            1,
            "ev_1_0",
            "0",
            "tool.exec",
            "worker_1",
            p,
            &format!("x:{p}:{{}}")
        ),
        compute_event_hash(
            1,
            "ev_1_0",
            "0",
            "tool.exec",
            &format!("worker_1:{p}:x"),
            p,
            "{}"
        ),
    );
    let mut ledger = InMemoryLedger::new();
    let actor = "svc-ci:on-behalf-of:alice";
    ledger
        .append("policy.override", actor, "{\"rule\":\"prod-freeze\"}")
        .unwrap();
    let mut events = ledger.all_events().unwrap();
    events[0].event_type = "policy.override:svc-ci:on-behalf-of".into();
    events[0].actor = "alice".into();
    assert!(!VerificationPolicy::default().verify(&events).unwrap().valid);
}

#[test]
fn f2_v2_golden_vectors_match_an_independent_python_implementation() {
    let id = "ev_0123456789abcdef0123456789abcdef_1";
    let actor = "arn:aws:iam::123456789012:user/alice";
    let payload = "{\"command\":\"build\"}";
    assert_eq!(
        compute_payload_digest(payload),
        "e053d91e793d447a4d3c889162d6303593a89b5c9323850ffcaa6465e5b42345"
    );
    let ts = "1760659200000000000";
    let h1 = compute_event_hash(1, id, ts, "tool.exec", actor, GENESIS_PREV_HASH, payload);
    assert_eq!(
        h1,
        "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b"
    );
    assert_eq!(
        compute_payload_digest("{}"),
        "98db375430d9d7e035552d94f599855e44b9257f5151438a065fa59c583ec93a"
    );
    let h2 = compute_event_hash(
        (1 << 40) + 1,
        "ev_0123456789abcdef0123456789abcdef_1099511627777",
        "1760659200000000001",
        "policy.override",
        "svc-ci:on-behalf-of:alice",
        &h1,
        "{}",
    );
    assert_eq!(
        h2,
        "27d2430b331e10c1899d323d86bf12ccadc7e8b07772d3941707717cc8a05273"
    );
}

#[test]
fn f3_signed_ledger_rejects_stripped_forged_and_foreign_signatures() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let mut ledger = InMemoryLedger::with_signing_key(key.clone());
    let ev = ledger.append("tool.exec", "worker_1", "{}").unwrap();
    assert!(ev.signature.is_some(), "append signs");
    let policy = VerificationPolicy {
        verifying_key: Some(key.verifying_key()),
        ..Default::default()
    };
    assert!(ledger.verify_chain_with(&policy).unwrap().valid);
    let honest = ledger.all_events().unwrap();
    let foreign = sign_event_hash_ed25519(&ev.event_hash, &[9u8; 32]);
    for tampered in [None, Some("ed25519:forged".to_string()), Some(foreign)] {
        let mut events = honest.clone();
        events[0].signature = tampered;
        assert!(!policy.verify(&events).unwrap().valid);
    }
    let mut events = honest.clone();
    events[0].payload = "{\"forged\":true}".into();
    relink(&mut events);
    assert!(
        !policy.verify(&events).unwrap().valid,
        "rewrite needs the private key"
    );
}

#[test]
fn f4_weak_keys_noncanonical_hex_and_untagged_signatures_are_rejected() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let universal = format!("ed25519:01{}{}", "00".repeat(31), "00".repeat(32));
    assert!(!verify_event_hash_ed25519(
        GENESIS_PREV_HASH,
        &universal,
        &identity
    ));

    let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
    let pk = key.verifying_key().to_bytes();
    let h = sha256_hex(b"event");
    let sig = sign_event_hash(&key, &h);
    assert!(verify_event_hash_ed25519(&h, &sig, &pk));
    let upper = sig.to_uppercase().replacen("ED25519", "ed25519", 1);
    assert!(!verify_event_hash_ed25519(&h, &upper, &pk));
    assert_eq!(decode_lower_hex::<1>("0a"), Some([10]));
    assert_eq!(decode_lower_hex::<1>("+a"), None);
    assert_eq!(decode_lower_hex::<1>("0A"), None);

    use ed25519_dalek::Signer;
    let bare: String = key
        .sign(h.as_bytes())
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        !verify_event_hash_ed25519(&h, &format!("ed25519:{bare}"), &pk),
        "no domain tag"
    );
}

#[test]
fn f5_only_canonical_payloads_are_recorded() {
    let mut ledger = InMemoryLedger::new();
    for rejected in [
        "{\"b\":2,\"a\":1}",
        "{\"a\": 1, \"b\": 2}",
        "{\"a\":1,\"b\":2,\"a\":1}",
        "{\"\\u0061\":1,\"b\":2}",
        "{\"a\":1.0,\"b\":2}",
        "{\"a\":9007199254740992}",
        "{\"a\":-0}",
        "{\"a\":{\"d\":1,\"c\":2}}",
        "[1,2]",
        "definitely not json",
    ] {
        let result = ledger.append("tool.exec", "worker_1", rejected);
        assert!(
            matches!(result, Err(LedgerError::InvalidInput(_))),
            "{rejected}"
        );
    }
    assert!(ledger.all_events().unwrap().is_empty());
    for accepted in [
        "{\"a\":1,\"b\":2}",
        "{}",
        "{\"a\":0,\"b\":{\"c\":[0,{\"d\":1,\"e\":2}]}}",
        "{\"k\":\"caf\u{e9} \\\"q\\\"\",\"n\":-9007199254740991}",
    ] {
        ledger.append("tool.exec", "worker_1", accepted).unwrap();
    }
}
