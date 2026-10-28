//! End-to-end tests for the `argus-verify` binary: it must fail closed and emit JSON that record
//! content cannot shape.

use std::path::PathBuf;
use std::process::Command;

use argus_ledger::{AuditLedgerWriter, FileLedger};

fn scratch(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("argus_cli_{name}_{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("audit.jsonl")
}

fn run(args: &[&str]) -> (i32, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_argus-verify"))
        .args(args)
        .output()
        .expect("spawn argus-verify");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let json: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{e}: {stdout:?} {stderr:?}"));
    (out.status.code().unwrap_or(-1), json, stderr)
}

fn two_good_events(path: &PathBuf) {
    let ledger = FileLedger::new(path).unwrap();
    ledger
        .append("agent.startup", "coordinator", "{\"status\":\"ok\"}")
        .unwrap();
    ledger
        .append("tool.exec", "worker_1", "{\"command\":\"test\"}")
        .unwrap();
}

#[test]
fn valid_ledger_reports_counts_and_exit_0() {
    let path = scratch("valid");
    two_good_events(&path);
    let (code, json, _) = run(&["--json", path.to_str().unwrap()]);
    assert_eq!(code, 0);
    assert_eq!(json["valid"], true);
    assert_eq!(json["total_events"], 2);
    assert_eq!(json["v2_events"], 2);
    assert_eq!(json["v1_legacy_events"], 0);
}

/// F2: a torn tail or a line with missing fields is an integrity failure at that position, not
/// something to skip.
#[test]
fn torn_tail_and_incomplete_records_fail_closed_at_their_position() {
    for (name, bad_line) in [
        ("torn", "{\"sequence\":3,\"event_id\":\"x\",\"tim"),
        ("not_object", "[1,2,3]"),
        ("missing_actor", "{\"sequence\":3,\"event_id\":\"x\",\"timestamp\":\"1\",\"event_type\":\"t\",\"payload\":{},\"prev_hash\":\"a\",\"event_hash\":\"b\"}"),
        ("garbage", "not json at all"),
    ] {
        let path = scratch(name);
        two_good_events(&path);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str(bad_line);
        content.push('\n');
        std::fs::write(&path, content).unwrap();

        let (code, json, _) = run(&["--json", path.to_str().unwrap()]);
        assert_eq!(code, 1, "{name}: {json}");
        assert_eq!(json["valid"], false, "{name}");
        assert_eq!(json["first_broken_sequence"], 3, "{name}: {json}");
    }
}

/// F8: record content must not be able to inject keys into the machine-readable output.
#[test]
fn record_content_cannot_inject_json_output() {
    let path = scratch("inject");
    two_good_events(&path);
    let content = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let mut second: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
    second["prev_hash"] = serde_json::Value::String("x\",\"valid\":true,\"pwn\":\"".into());
    lines[1] = second.to_string();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();

    let (code, json, _) = run(&["--json", path.to_str().unwrap()]);
    assert_eq!(code, 1);
    let obj = json.as_object().unwrap();
    assert_eq!(obj["valid"], false);
    assert!(obj.get("pwn").is_none());
    assert_eq!(
        obj.len(),
        5,
        "exactly valid, first_broken_sequence, error, warnings, elapsed_ms: {json}"
    );
    assert_eq!(obj["first_broken_sequence"], 2);
    assert_eq!(obj["warnings"], serde_json::json!([]));
}

/// Issue #14: `--legacy-timestamps-before` accepts a clock-step regression below the cutoff,
/// reports the count and warns once; at or above the cutoff, and for hash tampering anywhere,
/// the verdict stays FAILED. A cutoff of 0 is a usage error.
#[test]
fn legacy_timestamps_before_flag_accepts_historic_regressions_below_cutoff_only() {
    use argus_ledger::{compute_event_hash, AuditEvent};

    let path = scratch("legacy_ts");
    let ledger = FileLedger::new(&path).unwrap();
    for i in 0..10 {
        ledger
            .append("tool.exec", "worker_1", &format!("{{\"step\":{i}}}"))
            .unwrap();
    }
    let content = std::fs::read_to_string(&path).unwrap();
    let mut events: Vec<AuditEvent> = content
        .lines()
        .map(|l| AuditEvent::from_json_line(l).unwrap())
        .collect();
    // Record 5 is stamped with record 4's instant, then the chain is relinked from there so
    // only the timestamp rule is under test.
    events[4].timestamp = events[3].timestamp.clone();
    for i in 4..events.len() {
        events[i].prev_hash = events[i - 1].event_hash.clone();
        let ev = &events[i];
        events[i].event_hash = compute_event_hash(
            ev.sequence,
            &ev.event_id,
            &ev.timestamp,
            &ev.event_type,
            &ev.actor,
            &ev.prev_hash,
            &ev.payload,
        );
    }
    let lines: Vec<String> = events.iter().map(AuditEvent::to_json_line).collect();
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let file = path.to_str().unwrap();

    let (code, json, stderr) = run(&["--json", file]);
    assert_eq!(code, 1, "{json}");
    assert_eq!(json["first_broken_sequence"], 5);
    assert!(!stderr.contains("warning:"), "{stderr}");

    let (code, json, stderr) = run(&["--json", "--legacy-timestamps-before", "6", file]);
    assert_eq!(code, 0, "{json} {stderr}");
    assert_eq!(json["valid"], true);
    assert_eq!(json["total_events"], 10);
    assert_eq!(json["legacy_timestamp_regressions"], 1);
    let warnings = json["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{json}");
    assert!(warnings[0]
        .as_str()
        .unwrap()
        .contains("first at sequence 5"));
    assert_eq!(stderr.matches("warning:").count(), 1, "{stderr}");

    let (code, json, _) = run(&["--json", "--legacy-timestamps-before", "5", file]);
    assert_eq!(code, 1, "regression at the cutoff is strict: {json}");
    assert_eq!(json["first_broken_sequence"], 5);

    // Hash tampering below the cutoff: still FAILED at that position.
    let mut tampered = lines.clone();
    tampered[1] = tampered[1].replacen("\"step\":1", "\"step\":99", 1);
    std::fs::write(&path, tampered.join("\n") + "\n").unwrap();
    let (code, json, _) = run(&["--json", "--legacy-timestamps-before", "6", file]);
    assert_eq!(code, 1, "{json}");
    assert_eq!(json["first_broken_sequence"], 2);

    let out = Command::new(env!("CARGO_BIN_EXE_argus-verify"))
        .args(["--json", "--legacy-timestamps-before", "0", file])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn anchor_mismatch_and_missing_file_use_distinct_exit_codes() {
    let path = scratch("anchor");
    two_good_events(&path);
    let bogus = format!("2:{}", "0".repeat(64));
    let (code, json, _) = run(&["--json", "--anchor", &bogus, path.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(json["first_broken_sequence"], 2);
    let (code, json, _) = run(&[
        "--json",
        "--anchor",
        &format!("9:{}", "0".repeat(64)),
        path.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 1,
        "an anchor beyond the head means truncation: {json}"
    );

    let missing = path.with_file_name("missing.jsonl");
    let (code, json, _) = run(&["--json", missing.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert_eq!(json["valid"], false);
}


/// G-R1: Tracekit tail-cut reproduction and --anchor-file verification.
/// Without an anchor, a truncated chain (events 8..10 deleted) passes internal verification.
/// With an --anchor-file witnessing sequence 10, the tail-cut fails closed (exit 1).
#[test]
fn tracekit_tail_cut_detected_by_anchor_file() {
    let path = scratch("tracekit_tail_cut");
    let ledger = FileLedger::new(&path).unwrap();
    let mut head_hashes = Vec::new();
    for i in 1..=10 {
        let ev = ledger.append("task.event", "worker", &format!("{{\"step\":{i}}}")).unwrap();
        head_hashes.push((ev.sequence, ev.event_hash.clone(), ev.timestamp.clone()));
    }
    let (seq10, hash10, ts10) = &head_hashes[9];
    assert_eq!(*seq10, 10);

    // Create an anchor checkpoint file witnessing sequence 10.
    let anchor_file = path.with_file_name("checkpoints.json");
    let checkpoint = serde_json::json!({
        "checkpoints": [
            {
                "sequence": seq10,
                "head_hash": hash10,
                "timestamp": ts10
            }
        ]
    });
    std::fs::write(&anchor_file, checkpoint.to_string()).unwrap();

    // 1. Intact ledger with anchor file passes.
    let (code, json, stderr) = run(&["--json", "--anchor-file", anchor_file.to_str().unwrap(), path.to_str().unwrap()]);
    assert_eq!(code, 0, "intact ledger must pass: {json} {stderr}");
    assert_eq!(json["valid"], true);
    assert_eq!(json["total_events"], 10);

    // 2. Tracekit attack: cut off the tail (keep only first 7 lines).
    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let truncated_path = path.with_file_name("audit_truncated.jsonl");
    std::fs::write(&truncated_path, lines[..7].join("\n") + "\n").unwrap();

    // Tracekit property: WITHOUT anchor, truncated log passes internal checks.
    let (code_no_anchor, json_no_anchor, _) = run(&["--json", truncated_path.to_str().unwrap()]);
    assert_eq!(code_no_anchor, 0, "truncated chain internally valid without anchor");
    assert_eq!(json_no_anchor["valid"], true);
    assert_eq!(json_no_anchor["total_events"], 7);

    // G-R1 fix: WITH anchor file, the tail-cut attack is detected and fails closed (exit 1).
    let (code_anchored, json_anchored, stderr_anchored) = run(&[
        "--json",
        "--anchor-file",
        anchor_file.to_str().unwrap(),
        truncated_path.to_str().unwrap(),
    ]);
    assert_eq!(code_anchored, 1, "tail-cut must fail verification: {json_anchored} {stderr_anchored}");
    assert_eq!(json_anchored["valid"], false);
    assert_eq!(json_anchored["first_broken_sequence"], 10);

    // 3. Forged head at sequence 10 (key-holder re-sign / fork attack).
    let bogus_anchor = path.with_file_name("bogus_checkpoints.json");
    let bogus_checkpoint = serde_json::json!({
        "checkpoints": [
            {
                "sequence": 10,
                "head_hash": "0".repeat(64),
                "timestamp": ts10
            }
        ]
    });
    std::fs::write(&bogus_anchor, bogus_checkpoint.to_string()).unwrap();
    let (code_bogus, json_bogus, _) = run(&[
        "--json",
        "--anchor-file",
        bogus_anchor.to_str().unwrap(),
        path.to_str().unwrap(),
    ]);
    assert_eq!(code_bogus, 1, "forged hash must fail: {json_bogus}");
    assert_eq!(json_bogus["valid"], false);
    assert_eq!(json_bogus["first_broken_sequence"], 10);
}
