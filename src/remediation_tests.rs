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
