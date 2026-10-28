//! Regression tests for the remediation series; each stage appends the tests for its finding.
#[allow(unused_imports)]
use super::*;

fn ledger_with(n: usize) -> InMemoryLedger {
    let ledger = InMemoryLedger::new();
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
    let ledger = ledger_with(3);
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
    let ledger = InMemoryLedger::new();
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
    let ledger = InMemoryLedger::with_signing_key(key.clone());
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
    let ledger = InMemoryLedger::new();
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

#[test]
fn f6_failures_are_positional_typed_and_fail_closed() {
    let ledger = ledger_with(2);
    let mut events = ledger.all_events().unwrap();
    events[1].sequence = u64::MAX;
    let report = VerificationPolicy::default().verify(&events).unwrap();
    assert_eq!(
        report.first_broken_sequence,
        Some(2),
        "position, not the stored value"
    );
    assert!(matches!(
        report.ensure_valid(),
        Err(LedgerError::SequenceDiscontinuity(_))
    ));

    let mut events = ledger.all_events().unwrap();
    events[0].payload = "{\"x\":1}".into();
    let report = VerificationPolicy::default().verify(&events).unwrap();
    assert!(matches!(
        report.ensure_valid(),
        Err(LedgerError::HashMismatch(_))
    ));
    assert!(ledger.verify_chain().unwrap().ensure_valid().is_ok());
}

#[test]
fn f7_ledger_identity_resolution_and_monotonic_time() {
    let (a, b) = (InMemoryLedger::new(), InMemoryLedger::new());
    let ea = a.append("tool.exec", "worker_1", "{}").unwrap();
    let eb = b.append("tool.exec", "worker_1", "{}").unwrap();
    assert_ne!(ea.event_id, eb.event_id);
    assert_ne!(ea.event_hash, eb.event_hash);

    let stamps: Vec<u64> = (0..1000)
        .map(|_| {
            a.append("tool.exec", "worker_1", "{}")
                .unwrap()
                .timestamp
                .parse()
                .unwrap()
        })
        .collect();
    assert!(
        stamps.windows(2).all(|w| w[0] < w[1]),
        "strictly increasing"
    );
    assert!(a.verify_chain().unwrap().valid);

    let mut events = a.all_events().unwrap();
    events.last_mut().unwrap().timestamp = "0".into();
    relink(&mut events);
    let report = VerificationPolicy::default().verify(&events).unwrap();
    assert!(matches!(
        report.failure,
        Some(LedgerError::InvalidTimestamp(_))
    ));
}

#[test]
fn f8_identifiers_and_payload_size_are_validated_before_recording() {
    let ledger = InMemoryLedger::new();
    for (event_type, actor) in [
        ("", "worker_1"),
        ("tool.exec", ""),
        ("tool.exec\n2026-10-17 INFO approved by", "worker_1"),
        ("Tool.Exec", "worker_1"),
        ("tool..exec", "worker_1"),
        ("tool.exec", "\u{430}dmin"),
        ("tool.exec", "worker\u{0}1"),
        ("tool.exec", "worker 1"),
    ] {
        let result = ledger.append(event_type, actor, "{}");
        assert!(
            matches!(result, Err(LedgerError::InvalidInput(_))),
            "{event_type:?} {actor:?}"
        );
    }
    let oversized = format!("{{\"x\":\"{}\"}}", "A".repeat(MAX_PAYLOAD_BYTES));
    let result = ledger.append("bulk.ingest", "worker_1", &oversized);
    assert!(matches!(result, Err(LedgerError::InvalidInput(_))));
    assert!(ledger.all_events().unwrap().is_empty());
    ledger
        .append("tool.exec", "arn:aws:iam::123456789012:user/alice", "{}")
        .unwrap();
}

#[test]
fn f9_appends_proceed_while_a_large_chain_is_verified() {
    let ledger = InMemoryLedger::new();
    let blob = format!("{{\"blob\":\"{}\"}}", "a".repeat(MAX_PAYLOAD_BYTES - 16));
    for _ in 0..32 {
        ledger.append("bulk.ingest", "worker_1", &blob).unwrap();
    }
    let reader = ledger.clone();
    let verifier = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        assert!(reader.verify_chain().unwrap().valid);
        started.elapsed()
    });
    let (mut worst, mut appends) = (std::time::Duration::ZERO, 0u32);
    while !verifier.is_finished() {
        let started = std::time::Instant::now();
        ledger.append("tool.exec", "worker_1", "{}").unwrap();
        worst = worst.max(started.elapsed());
        appends += 1;
    }
    let verify_time = verifier.join().unwrap();
    assert!(appends > 0);
    assert!(
        worst * 4 < verify_time,
        "append waited {worst:?} during a {verify_time:?} verify"
    );
}

#[test]
fn f10_poisoned_lock_is_recovered_without_data_loss() {
    let ledger = ledger_with(1);
    let shared = ledger.clone();
    let _ = std::thread::spawn(move || {
        let _guard = shared.events.lock().unwrap();
        panic!("simulated panic inside the critical section");
    })
    .join();
    assert!(ledger.events.is_poisoned());
    ledger.append("tool.exec", "worker_1", "{}").unwrap();
    assert!(!ledger.events.is_poisoned());
    assert_eq!(ledger.all_events().unwrap().len(), 2);
    assert!(ledger.verify_chain().unwrap().valid);
}

mod probe {
    //! Per-thread live-heap counter (realloc = alloc + copy + free, an upper bound).
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    struct Probe;

    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let ptr = unsafe { System.alloc(layout) };
            if !ptr.is_null() {
                track(layout.size() as isize);
            }
            ptr
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) };
            track(-(layout.size() as isize));
        }
    }

    fn track(delta: isize) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    #[global_allocator]
    static GLOBAL: Probe = Probe;

    pub fn peak_during<R>(f: impl FnOnce() -> R) -> (R, usize) {
        let base = LIVE.with(Cell::get);
        PEAK.with(|p| p.set(base));
        let out = f();
        (out, (PEAK.with(Cell::get) - base).max(0) as usize)
    }
}

#[test]
fn f11_hashing_streams_without_copying_the_input() {
    let input = vec![b'a'; 1 << 20];
    let (digest, peak) = probe::peak_during(|| sha256_hex(&input));
    assert_eq!(digest.len(), 64);
    assert!(peak <= 128, "sha256_hex(1 MiB) peak {peak} B");
    let payload = format!("{{\"blob\":\"{}\"}}", "a".repeat(1 << 20));
    let (_, peak) = probe::peak_during(|| compute_payload_digest(&payload));
    assert!(peak <= 128, "compute_payload_digest(1 MiB) peak {peak} B");
}

#[test]
fn f12_one_ledger_is_shared_across_threads_without_an_outer_lock() {
    let ledger = Arc::new(InMemoryLedger::new());
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let ledger = Arc::clone(&ledger);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    ledger
                        .append("tool.exec", &format!("agent_{i}"), "{}")
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(ledger.all_events().unwrap().len(), 400);
    assert!(ledger.verify_chain().unwrap().valid);
}

#[test]
#[ignore = "timing harness; run with --release -- --ignored --nocapture"]
fn measure_fixed_lock_hold() {
    use std::time::{Duration, Instant};
    let ledger = Arc::new(InMemoryLedger::new());
    let blob = format!("{{\"blob\":\"{}\"}}", "a".repeat(MAX_PAYLOAD_BYTES - 16));
    for _ in 0..64 {
        ledger.append("bulk.ingest", "worker_1", &blob).unwrap();
    }

    let writer = {
        let (ledger, blob) = (Arc::clone(&ledger), blob.clone());
        std::thread::spawn(move || {
            let started = Instant::now();
            for _ in 0..32 {
                ledger.append("bulk.ingest", "worker_1", &blob).unwrap();
            }
            started.elapsed() / 32
        })
    };
    let mut worst_head = Duration::ZERO;
    while !writer.is_finished() {
        let started = Instant::now();
        let _ = ledger.head().unwrap();
        worst_head = worst_head.max(started.elapsed());
    }
    let per_append = writer.join().unwrap();
    println!(
        "[measure-fixed] 1 MiB append avg {per_append:?}; worst head() meanwhile {worst_head:?}"
    );

    let reader = Arc::clone(&ledger);
    let verifier = std::thread::spawn(move || {
        let started = Instant::now();
        assert!(reader.verify_chain().unwrap().valid);
        started.elapsed()
    });
    let mut worst_append = Duration::ZERO;
    while !verifier.is_finished() {
        let started = Instant::now();
        ledger.append("tool.exec", "worker_1", "{}").unwrap();
        worst_append = worst_append.max(started.elapsed());
    }
    let verify_time = verifier.join().unwrap();
    println!("[measure-fixed] verify_chain(96 x 1 MiB) {verify_time:?}; worst 2-byte append meanwhile {worst_append:?}");
}

#[test]
fn opt_table_hex_matches_formatted_hex() {
    for b in 0..=u8::MAX {
        assert_eq!(hex_lower(&[b]), format!("{b:02x}"));
    }
    let digest: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0xa5);
    let formatted: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex_string(digest_hex(&digest)), formatted);
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn opt_canonical_u64_parse_matches_the_allocating_reference() {
    let reference = |s: &str| s.parse().ok().filter(|v: &u64| v.to_string() == s);
    for s in [
        "",
        "0",
        "00",
        "01",
        "1",
        "+1",
        "-1",
        " 1",
        "1 ",
        "1_000",
        "\u{0661}",
        "18446744073709551615",
        "18446744073709551616",
        "018446744073709551615",
        "1783000000000000000",
    ] {
        assert_eq!(parse_timestamp_nanos(s), reference(s), "input {s:?}");
    }
}

#[test]
fn opt_streaming_canonical_check_matches_reserialization() {
    for (payload, canonical) in [
        ("{\"a\":1}", true),
        ("{\"a\":1} ", false),
        (" {\"a\":1}", false),
        ("{\"a\":1}{", false),
        ("{\"a\": 1}", false),
        ("{\"a\":\"\\u0041\"}", false),
        ("{\"a\":\"\\n\"}", true),
        ("{\"a\":[1,{\"b\":null,\"c\":true}],\"d\":\"\u{e9}\"}", true),
        ("{}", true),
    ] {
        assert_eq!(
            validate_canonical_payload(payload).is_ok(),
            canonical,
            "payload {payload:?}"
        );
    }
}

#[test]
fn f4_signatures_match_an_independent_openssl_implementation() {
    // Ed25519 is deterministic: the Python package (OpenSSL via `cryptography`) produces the same
    // signature over the domain-tagged golden event hash for seed 07 * 32.
    let seed = [7u8; 32];
    let event_hash = "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b";
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(
        hex_lower(public.as_bytes()),
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
    let signature = sign_event_hash_ed25519(event_hash, &seed);
    assert_eq!(
        signature,
        "ed25519:73124ea3a9e12a395d4670806d1f1ca21debfa1d1d53949dac5718844ca64748\
         7b2d6eaf76e8593785308bb522b4a73ced14a206fd2d3327a1b7625a2ba36706"
    );
    assert!(verify_event_hash_ed25519(
        event_hash,
        &signature,
        public.as_bytes()
    ));
}

#[test]
fn test_file_ledger_create_permissions_and_sync() {
    let tmp = tempfile_dir("file_ledger_perms");
    let path = tmp.join("audit.jsonl");

    let ledger = crate::FileLedger::new(&path).expect("open ledger");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&path).expect("metadata");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o600,
            "ledger file must be created with 0600 permissions"
        );
    }

    let ev1 = ledger
        .append("agent.startup", "coordinator", "{\"status\":\"ok\"}")
        .expect("append ev1");
    assert_eq!(ev1.sequence, 1);
    assert_eq!(ev1.prev_hash, GENESIS_PREV_HASH);

    let ev2 = ledger
        .append("tool.exec", "worker_1", "{\"command\":\"test\"}")
        .expect("append ev2");
    assert_eq!(ev2.sequence, 2);
    assert_eq!(ev2.prev_hash, ev1.event_hash);

    let head = ledger.head().expect("head").expect("some head");
    assert_eq!(head.sequence, 2);
    assert_eq!(head.event_hash, ev2.event_hash);

    let report = ledger.verify_chain().expect("verify");
    assert!(report.valid);
    assert_eq!(report.total_events, 2);

    std::fs::remove_dir_all(tmp).ok();
}

#[test]
fn test_file_ledger_golden_hash_parity_and_cross_compat() {
    let tmp = tempfile_dir("file_ledger_golden");
    let path = tmp.join("audit.jsonl");

    let ledger = crate::FileLedger::new(&path).expect("open");

    // Golden vector 1: "{\"command\":\"build\"}"
    let payload1 = "{\"command\":\"build\"}";
    let digest1 = crate::compute_payload_digest(payload1);
    assert_eq!(
        digest1,
        "e053d91e793d447a4d3c889162d6303593a89b5c9323850ffcaa6465e5b42345"
    );

    // Empty payload digest: "{}"
    let digest_empty = crate::compute_payload_digest("{}");
    assert_eq!(
        digest_empty,
        "98db375430d9d7e035552d94f599855e44b9257f5151438a065fa59c583ec93a"
    );

    let ev = ledger
        .append(
            "tool.exec",
            "arn:aws:iam::123456789012:user/alice",
            payload1,
        )
        .expect("append");

    // Override event_hash computation test against golden hash
    let golden_event_hash = crate::compute_event_hash(
        1,
        "ev_0123456789abcdef0123456789abcdef_1",
        "1760659200000000000",
        "tool.exec",
        "arn:aws:iam::123456789012:user/alice",
        GENESIS_PREV_HASH,
        payload1,
    );
    assert_eq!(
        golden_event_hash,
        "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b"
    );

    // Verify all_events reads correctly
    let all = ledger.all_events().expect("all_events");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].sequence, 1);
    assert_eq!(all[0].event_hash, ev.event_hash);

    let report = ledger.verify_chain().expect("verify");
    assert!(report.valid);

    std::fs::remove_dir_all(tmp).ok();
}

// ---------------------------------------------------------------------------------------------
// 2026-10-28 review repair set. Tests are named `rv_<finding>_...`.
// ---------------------------------------------------------------------------------------------

/// Every byte the identifier grammar accepts must survive `to_json_line` -> `from_json_line`
/// unchanged, otherwise the writer can produce a record its own reader rejects.
#[test]
fn rv_f1_every_accepted_identifier_byte_round_trips_through_the_json_line() {
    let ledger = InMemoryLedger::new();
    let mut accepted_actor_bytes = 0;
    for b in 0u8..=0x7f {
        let actor = format!("x{}y", b as char);
        if validate_identifiers("t.e", &actor).is_err() {
            continue;
        }
        accepted_actor_bytes += 1;
        let ev = ledger.append("t.e", &actor, "{}").unwrap();
        let line = ev.to_json_line();
        assert_eq!(
            AuditEvent::from_json_line(&line).unwrap(),
            ev,
            "actor byte {b:#04x}"
        );
    }
    // 0x21..=0x7e is 94 graphic bytes; minus '"' and '\' leaves 92.
    assert_eq!(accepted_actor_bytes, 92);
    for b in 0u8..=0x7f {
        let event_type = format!("a{}b", b as char);
        if validate_identifiers(&event_type, "w").is_err() {
            continue;
        }
        let ev = ledger.append(&event_type, "w", "{}").unwrap();
        assert_eq!(AuditEvent::from_json_line(&ev.to_json_line()).unwrap(), ev);
    }
    assert!(ledger.verify_chain().unwrap().valid);
}

#[test]
fn rv_f1_actor_with_quote_or_backslash_is_rejected_before_recording() {
    let ledger = InMemoryLedger::new();
    for actor in ["a\"b", "a\\b", "\"", "\\", "a\\\"b"] {
        let result = ledger.append("tool.exec", actor, "{}");
        assert!(
            matches!(result, Err(LedgerError::InvalidInput(_))),
            "{actor:?}"
        );
    }
    assert!(ledger.all_events().unwrap().is_empty());
}

/// The serializer must escape even what the grammar should have stopped (defense in depth), and
/// a signature is quoted too.
#[test]
fn rv_f1_hand_built_event_with_json_syntax_in_strings_still_parses_back() {
    let mut ev = ledger_with(1).all_events().unwrap().remove(0);
    ev.actor = "a\"b\\c\n\u{1}".into();
    ev.event_id = "id\"".into();
    ev.timestamp = "ts\\".into();
    ev.event_type = "x\"y".into();
    ev.signature = Some("sig\"\\".into());
    let line = ev.to_json_line();
    assert!(!line.contains('\n'), "a record is exactly one line");
    assert_eq!(AuditEvent::from_json_line(&line).unwrap(), ev);
}

/// Byte-for-byte compatibility with the record format every release so far has written and
/// the Python writer produces: same field order, `"signature":null` when unsigned.
#[test]
fn rv_f1_json_line_bytes_and_field_order_are_unchanged() {
    let ev = AuditEvent {
        sequence: 1,
        event_id: "ev_0123456789abcdef0123456789abcdef_1".into(),
        timestamp: "1760659200000000000".into(),
        event_type: "tool.exec".into(),
        actor: "arn:aws:iam::123456789012:user/alice".into(),
        payload: "{\"command\":\"build\"}".into(),
        prev_hash: GENESIS_PREV_HASH.into(),
        event_hash: "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b".into(),
        signature: None,
        hash_version: 2,
    };
    assert_eq!(
        ev.to_json_line(),
        "{\"sequence\":1,\"event_id\":\"ev_0123456789abcdef0123456789abcdef_1\",\
         \"timestamp\":\"1760659200000000000\",\"event_type\":\"tool.exec\",\
         \"actor\":\"arn:aws:iam::123456789012:user/alice\",\"payload\":{\"command\":\"build\"},\
         \"prev_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
         \"event_hash\":\"3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b\",\
         \"signature\":null,\"hash_version\":2}"
    );
    let signed = AuditEvent {
        signature: Some("ed25519:00".into()),
        payload: "{\"k\":[1,{\"n\":null}],\"u\":\"\u{e9}\"}".into(),
        ..ev
    };
    let line = signed.to_json_line();
    assert!(line.contains(",\"signature\":\"ed25519:00\",\"hash_version\":2}"));
    // The payload is spliced in verbatim: non-ASCII stays unescaped, as the Python writer does.
    assert!(line.contains("\"payload\":{\"k\":[1,{\"n\":null}],\"u\":\"\u{e9}\"},"));
}

/// A ledger that spans the format change (format-1 records, then format-2) must verify in the
/// library exactly as it does in the Python package and the CLI, and relabelling a record's
/// format must not make it verify.
#[test]
fn rv_f17_legacy_format_1_records_verify_and_cannot_be_relabelled() {
    let v1 = |sequence: u64, prev_hash: &str, payload: &str| {
        let mut ev = AuditEvent {
            sequence,
            event_id: format!("legacy-{sequence}"),
            timestamp: format!("2026-10-0{sequence}T00:00:00+00:00"),
            event_type: "tool.exec".into(),
            actor: "agent".into(),
            payload: payload.into(),
            prev_hash: prev_hash.into(),
            event_hash: String::new(),
            signature: None,
            hash_version: 1,
        };
        ev.event_hash = legacy_v1_event_hash(&ev);
        ev
    };
    let e1 = v1(1, GENESIS_PREV_HASH, "{\"i\":1}");
    let e2 = v1(2, &e1.event_hash, "{\"i\":2}");
    let mut e3 = AuditEvent {
        sequence: 3,
        event_id: "ev_3".into(),
        timestamp: "2026-10-03T00:00:00+00:00".into(),
        event_type: "tool.exec".into(),
        actor: "agent".into(),
        payload: "{\"i\":3}".into(),
        prev_hash: e2.event_hash.clone(),
        event_hash: String::new(),
        signature: None,
        hash_version: 2,
    };
    e3.event_hash = compute_event_hash(
        3,
        &e3.event_id,
        &e3.timestamp,
        &e3.event_type,
        &e3.actor,
        &e3.prev_hash,
        &e3.payload,
    );
    // Matches the Python reference `compute_event_hash(..., hash_version=1)`.
    assert_eq!(
        e1.event_hash,
        sha256_hex(
            format!(
                "1:legacy-1:2026-10-01T00:00:00+00:00:tool.exec:agent:{GENESIS_PREV_HASH}:{{\"i\":1}}"
            )
            .as_bytes()
        )
    );

    let report = VerificationPolicy::default()
        .verify(&[e1.clone(), e2.clone(), e3.clone()])
        .unwrap();
    assert!(report.valid, "{:?}", report.error_detail);
    assert_eq!((report.total_events, report.legacy_events), (3, 2));

    // A record parsed from a line without hash_version is format 1 and round-trips as such.
    let line = e1.to_json_line().replace(",\"hash_version\":1}", "}");
    let parsed = AuditEvent::from_json_line(&line).unwrap();
    assert_eq!(parsed, e1);
    assert!(AuditEvent::from_json_line(&line.replace('}', ",\"hash_version\":3}")).is_err());

    for (position, relabel) in [(1usize, 2u8), (2, 2), (3, 1)] {
        let mut events = vec![e1.clone(), e2.clone(), e3.clone()];
        events[position - 1].hash_version = relabel;
        let report = VerificationPolicy::default().verify(&events).unwrap();
        assert_eq!(report.first_broken_sequence, Some(position as u64));
        assert!(matches!(report.failure, Some(LedgerError::HashMismatch(_))));
    }
}

/// F3: a long ledger verifies in one pass from disk, and a fault at the end is still found at
/// the right position. Correctness over a 50k-record file; memory is checked by inspection
/// (`verify_chain_with` never builds a `Vec<AuditEvent>`).
#[test]
fn rv_f3_file_ledger_verifies_50k_records_streaming_and_finds_a_fault_at_the_tail() {
    let dir = tempfile_dir("rv_f3");
    let path = dir.join("audit.jsonl");
    const N: u64 = 50_000;
    // Build the chain in memory (FileLedger::append syncs every record, which is the point of
    // the writer but far too slow for 50k test records) and write it as one file.
    let source = InMemoryLedger::new();
    let mut content = String::new();
    for i in 0..N {
        let ev = source
            .append("tool.exec", "agent", &format!("{{\"i\":{i}}}"))
            .unwrap();
        content.push_str(&ev.to_json_line());
        content.push('\n');
    }
    std::fs::write(&path, &content).unwrap();
    let ledger = FileLedger::new(&path).unwrap();
    let report = ledger.verify_chain().unwrap();
    assert!(report.valid, "{:?}", report.error_detail);
    assert_eq!(report.total_events, N as usize);
    assert_eq!(report.head_hash, ledger.head().unwrap().unwrap().event_hash);

    let anchor = ChainAnchor {
        sequence: N,
        event_hash: report.head_hash.clone(),
    };
    let policy = VerificationPolicy {
        anchor: Some(anchor),
        verifying_key: None,
        legacy_timestamps_before: None,
    };
    assert!(ledger.verify_chain_with(&policy).unwrap().valid);

    // Flip one payload byte in the last record: found at position N with the right counts.
    let last_payload = format!("\"i\":{}", N - 1);
    let pos = content.rfind(&last_payload).unwrap();
    content.replace_range(pos..pos + last_payload.len(), &format!("\"i\":{N}"));
    std::fs::write(&path, &content).unwrap();
    let report = ledger.verify_chain().unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_broken_sequence, Some(N));
    assert_eq!(report.total_events, N as usize);
    assert!(matches!(report.failure, Some(LedgerError::HashMismatch(_))));

    // Truncate the tail: the anchor is no longer witnessed.
    let keep = content.rfind('\n').unwrap();
    std::fs::write(&path, &content[..keep]).unwrap();
    let report = ledger.verify_chain_with(&policy).unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_broken_sequence, Some(N));
    let _ = std::fs::remove_dir_all(dir);
}

/// A line that is not a record fails the library verifier at its position, with the same
/// report shape the Python package produces.
#[test]
fn rv_f2_file_ledger_verify_fails_closed_on_a_malformed_line() {
    let dir = tempfile_dir("rv_f2");
    let path = dir.join("audit.jsonl");
    let ledger = FileLedger::new(&path).unwrap();
    ledger.append("a.b", "x", "{}").unwrap();
    let ev2 = ledger.append("a.b", "x", "{}").unwrap();
    let mut content = std::fs::read_to_string(&path).unwrap();
    content.push_str("{\"sequence\":3,\"event_id\":\"torn\n");
    std::fs::write(&path, content).unwrap();
    let report = ledger.verify_chain().unwrap();
    assert!(!report.valid);
    assert_eq!(report.first_broken_sequence, Some(3));
    assert_eq!(report.total_events, 3);
    assert!(matches!(report.failure, Some(LedgerError::InvalidInput(_))));
    assert_eq!(report.head_hash, ev2.event_hash);
    let _ = std::fs::remove_dir_all(dir);
}

/// F5: timestamps compare as instants whatever their written form, so the Python package's
/// RFC 3339 records (with `+00:00`, another offset, `Z` or no suffix) and the Rust writers'
/// nanosecond integers obey one strictly-increasing rule.
#[test]
fn rv_f5_timestamps_parse_as_instants_across_offsets_and_forms() {
    const T: u64 = 1_793_145_600_000_000_000; // 2026-10-28T00:00:00Z
    for (text, expect) in [
        ("1793145600000000000", Some(T)),
        ("2026-10-28T00:00:00+00:00", Some(T)),
        ("2026-10-28T00:00:00Z", Some(T)),
        ("2026-10-28T00:00:00", Some(T)),
        ("2026-10-28T05:00:00+05:00", Some(T)),
        ("2026-10-27T19:30:00-04:30", Some(T)),
        ("2026-10-28T00:00:00.123456+00:00", Some(T + 123_456_000)),
        ("2026-10-28T00:00:00.123456789Z", Some(T + 123_456_789)),
        ("2026-10-28T00:00:00.1234567891Z", Some(T + 123_456_789)),
        ("2026-10-28T00:00:00.+00:00", None),
        ("2026-10-28T00:00:00+0500", None),
        ("2026-10-28T00:00:00+15:00", None),
        ("2026-10-28T00:00:00+05:60", None),
        ("2026-10-28T00:00:00x", None),
        ("2026-13-28T00:00:00Z", None),
        ("01793145600000000000", None),
        ("", None),
    ] {
        assert_eq!(parse_timestamp_nanos(text), expect, "{text:?}");
    }
    // Textually later, earlier as an instant: the verifier must compare instants.
    let a = parse_timestamp_nanos("2026-10-28T00:00:00+00:00").unwrap();
    let b = parse_timestamp_nanos("2026-10-28T04:59:59+05:00").unwrap();
    assert!(b < a);
}

/// A Rust writer appending after a Python record (RFC 3339) still produces a strictly later
/// instant, even if the host clock is behind that record.
#[test]
fn rv_f5_rust_writer_stays_monotonic_after_a_python_written_record() {
    let dir = tempfile_dir("rv_f5");
    let path = dir.join("audit.jsonl");
    let far_future = "2500-01-01T00:00:00.000000+00:00";
    let mut first = AuditEvent {
        sequence: 1,
        event_id: "py-1".into(),
        timestamp: far_future.into(),
        event_type: "tool.exec".into(),
        actor: "agent".into(),
        payload: "{}".into(),
        prev_hash: GENESIS_PREV_HASH.into(),
        event_hash: String::new(),
        signature: None,
        hash_version: 2,
    };
    first.event_hash = compute_event_hash(
        1,
        "py-1",
        far_future,
        "tool.exec",
        "agent",
        GENESIS_PREV_HASH,
        "{}",
    );
    std::fs::write(&path, first.to_json_line() + "\n").unwrap();
    let ledger = FileLedger::new(&path).unwrap();
    let second = ledger.append("tool.exec", "agent", "{}").unwrap();
    assert_eq!(
        parse_timestamp_nanos(&second.timestamp),
        Some(parse_timestamp_nanos(far_future).unwrap() + 1)
    );
    let report = ledger.verify_chain().unwrap();
    assert!(report.valid, "{:?}", report.error_detail);
    let _ = std::fs::remove_dir_all(dir);
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("argus_test_{}_{}", prefix, nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Issue #14: a ledger written before the strict timestamp rule can carry a clock-step
/// regression. `legacy_timestamps_before` accepts regressions below the cutoff, counts them and
/// warns once; everything else (hashes, links, sequence, the rule at or above the cutoff) stays
/// strict, and `Some(0)` is refused.
#[test]
fn issue14_legacy_timestamps_before_accepts_historic_regressions_only_below_the_cutoff() {
    let ledger = ledger_with(10);
    let mut events = ledger.all_events().unwrap();
    // Record 5 is stamped with record 4's instant: not strictly after its predecessor.
    events[4].timestamp = events[3].timestamp.clone();
    relink(&mut events);

    let strict = VerificationPolicy::default().verify(&events).unwrap();
    assert_eq!(strict.first_broken_sequence, Some(5));
    assert!(matches!(
        strict.failure,
        Some(LedgerError::InvalidTimestamp(_))
    ));
    assert_eq!(strict.legacy_timestamp_regressions, 0);
    assert!(strict.warnings.is_empty());

    let with_cutoff = |cutoff: u64| {
        VerificationPolicy {
            legacy_timestamps_before: Some(cutoff),
            ..Default::default()
        }
        .verify(&events)
    };

    let historic = with_cutoff(6).unwrap();
    assert!(historic.valid, "{:?}", historic.error_detail);
    assert_eq!(historic.total_events, 10);
    assert_eq!(historic.legacy_timestamp_regressions, 1);
    assert_eq!(historic.warnings.len(), 1);
    assert!(
        historic.warnings[0].contains("first at sequence 5"),
        "{:?}",
        historic.warnings
    );

    // The regression sits at the cutoff, so the strict rule applies to it.
    let at_cutoff = with_cutoff(5).unwrap();
    assert_eq!(at_cutoff.first_broken_sequence, Some(5));
    assert!(matches!(
        at_cutoff.failure,
        Some(LedgerError::InvalidTimestamp(_))
    ));

    // Sequence numbers start at 1; a cutoff of 0 is a caller error, not "unset".
    assert!(matches!(with_cutoff(0), Err(LedgerError::InvalidInput(_))));

    // Hash tampering below the cutoff is still a failure: the option relaxes timestamp order
    // only. The chain breaks at 2, before the regression is reached, so nothing is counted.
    let mut tampered = events.clone();
    tampered[1].payload = "{\"step\":99}".into();
    let report = with_cutoff(6).unwrap_or_else(|e| panic!("{e}"));
    assert!(report.valid);
    let report = VerificationPolicy {
        legacy_timestamps_before: Some(6),
        ..Default::default()
    }
    .verify(&tampered)
    .unwrap();
    assert_eq!(report.first_broken_sequence, Some(2));
    assert!(matches!(report.failure, Some(LedgerError::HashMismatch(_))));
    assert_eq!(report.legacy_timestamp_regressions, 0);

    // A malformed timestamp below the cutoff is still a failure.
    let mut malformed = events.clone();
    malformed[2].timestamp = "not-a-time".into();
    relink(&mut malformed);
    let report = VerificationPolicy {
        legacy_timestamps_before: Some(6),
        ..Default::default()
    }
    .verify(&malformed)
    .unwrap();
    assert_eq!(report.first_broken_sequence, Some(3));
    assert!(matches!(
        report.failure,
        Some(LedgerError::InvalidTimestamp(_))
    ));
}
