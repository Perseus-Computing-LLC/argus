use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn compute_v1(seq: u64, id: &str, ts: &str, et: &str, actor: &str, prev: &str, payload_json: &str) -> String {
    let header = format!("{seq}:{id}:{ts}:{et}:{actor}:{prev}:");
    let mut input = Vec::with_capacity(header.len() + payload_json.len());
    input.extend_from_slice(header.as_bytes());
    input.extend_from_slice(payload_json.as_bytes());
    argus_ledger::sha256_hex(&input)
}

fn main() {
    let path = "/opt/data/runtime/argus/audit.jsonl";
    let file = File::open(path).expect("open file");
    let reader = BufReader::new(file);

    let mut lines = Vec::new();
    for l in reader.lines() {
        if let Ok(line) = l {
            if !line.trim().is_empty() {
                lines.push(line);
            }
        }
    }
    println!("Loaded {} lines from {}", lines.len(), path);

    let t0 = Instant::now();
    let mut v1_verified = 0;
    let mut v2_verified = 0;
    let mut failed = 0;

    for (idx, line) in lines.iter().enumerate() {
        let val: serde_json::Value = serde_json::from_str(line).expect("json parse");
        let obj = val.as_object().expect("object");
        let seq = obj.get("sequence").and_then(|v| v.as_u64()).unwrap();
        let id = obj.get("event_id").and_then(|v| v.as_str()).unwrap();
        let ts = obj.get("timestamp").and_then(|v| v.as_str()).unwrap();
        let et = obj.get("event_type").and_then(|v| v.as_str()).unwrap();
        let actor = obj.get("actor").and_then(|v| v.as_str()).unwrap();
        let prev = obj.get("prev_hash").and_then(|v| v.as_str()).unwrap();
        let ev_hash = obj.get("event_hash").and_then(|v| v.as_str()).unwrap();
        let payload_val = obj.get("payload").unwrap();
        let payload_str = serde_json::to_string(payload_val).unwrap();

        let hash_version = obj.get("hash_version").and_then(|v| v.as_u64());

        let computed = if hash_version == Some(2) {
            let digest = argus_ledger::compute_payload_digest(&payload_str);
            argus_ledger::compute_event_hash_from_digest(seq, id, ts, et, actor, prev, &digest)
        } else {
            compute_v1(seq, id, ts, et, actor, prev, &payload_str)
        };

        if computed == ev_hash {
            if hash_version == Some(2) {
                v2_verified += 1;
            } else {
                v1_verified += 1;
            }
        } else {
            failed += 1;
            if failed == 1 {
                eprintln!("Mismatch at seq {seq}: computed {computed} vs recorded {ev_hash}");
            }
        }
    }

    let elapsed = t0.elapsed();
    let ms = elapsed.as_secs_f64() * 1000.0;
    let total = v1_verified + v2_verified;
    println!("Verified {} events (v1: {}, v2: {}, failed: {}) in {:.2} ms ({:.0} ev/s)",
             total, v1_verified, v2_verified, failed, ms, (total as f64) / elapsed.as_secs_f64());
}
