use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

fn main() {
    let path = "/opt/data/runtime/argus/audit.jsonl";
    let file = File::open(path).expect("open file");
    let reader = BufReader::new(file);

    let mut parsed_events = Vec::new();
    for l in reader.lines().map_while(Result::ok) {
        if l.contains("\"hash_version\":2") || l.contains("\"hash_version\": 2") {
            if let Ok(ev) = argus_ledger::AuditEvent::from_json_line(&l) {
                parsed_events.push(ev);
            }
        }
    }
    println!("Preloaded {} parsed v2 events", parsed_events.len());

    let t0 = Instant::now();
    let mut verified = 0usize;
    for ev in &parsed_events {
        let digest = argus_ledger::compute_payload_digest(&ev.payload);
        let h = argus_ledger::compute_event_hash_from_digest(
            ev.sequence,
            &ev.event_id,
            &ev.timestamp,
            &ev.event_type,
            &ev.actor,
            &ev.prev_hash,
            &digest,
        );
        if h == ev.event_hash {
            verified += 1;
        }
    }
    let elapsed = t0.elapsed();
    let ms = elapsed.as_secs_f64() * 1000.0;
    let rate = (verified as f64) / elapsed.as_secs_f64();
    println!(
        "Rust verified {}/{} hashes in {:.2} ms ({:.0} events/sec)",
        verified,
        parsed_events.len(),
        ms,
        rate
    );
}
