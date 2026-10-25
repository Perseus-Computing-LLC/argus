use std::time::Instant;
use argus_ledger::FileLedger;
use std::io::{BufRead, BufReader};
use std::fs::File;

fn main() {
    println!("Argus Rust Live Ledger Verification Benchmark");
    let path = "/opt/data/runtime/argus/audit.jsonl";
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open {path}: {e}");
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut v2_lines = Vec::new();
    for line in reader.lines() {
        if let Ok(l) = line {
            if l.contains("\"hash_version\":2") || l.contains("\"hash_version\": 2") {
                v2_lines.push(l);
            }
        }
    }

    println!("Loaded {} v2 events from live audit.jsonl", v2_lines.len());
    let t0 = Instant::now();
    // Parse and verify hashes
    let mut verified_count = 0usize;
    for line in &v2_lines {
        if let Ok(ev) = argus_ledger::AuditEvent::from_json_line(line) {
            let digest = argus_ledger::compute_payload_digest(&ev.payload);
            let computed_hash = argus_ledger::compute_event_hash_from_digest(
                ev.sequence,
                &ev.event_id,
                &ev.timestamp,
                &ev.event_type,
                &ev.actor,
                &ev.prev_hash,
                &digest,
            );
            if computed_hash == ev.event_hash {
                verified_count += 1;
            }
        }
    }
    let elapsed = t0.elapsed();
    println!("Verified {} / {} v2 event hashes in {:?}", verified_count, v2_lines.len(), elapsed);
    if verified_count > 0 {
        let rate = (verified_count as f64) / elapsed.as_secs_f64();
        println!("Throughput: {:.1} events/sec ({:.2} ms total)", rate, elapsed.as_secs_f64() * 1000.0);
    }
}
