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
