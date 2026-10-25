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
        assert_eq!(parse_canonical_u64(s), reference(s), "input {s:?}");
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
        .append("tool.exec", "arn:aws:iam::123456789012:user/alice", payload1)
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
