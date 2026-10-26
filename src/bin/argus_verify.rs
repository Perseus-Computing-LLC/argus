//! `argus-verify`: high-performance cryptographic audit verifier CLI for Argus ledgers.
//!
//! Verifies SHA-256 hash chains, sequence continuity, prev_hash links, and optional
//! witness anchors across millions of events per second with zero external dependencies.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn print_help() {
    println!(
        r#"argus-verify {} - Fast cryptographic ledger verifier for Argus audit trails

USAGE:
    argus-verify [OPTIONS] [LEDGER_FILE]

ARGS:
    <LEDGER_FILE>    Path to Argus audit.jsonl (default: ARGUS_AUDIT_PATH or /opt/data/runtime/argus/audit.jsonl)

OPTIONS:
    --anchor <SEQ>:<HASH>   Verify the chain witnesses a known sequence and event hash
    --benchmark, -b         Run 5 iterations to measure wall-clock latency and throughput
    --json                  Output results in structured machine-readable JSON
    --help, -h              Print this help text
    --version, -v           Print version information

EXIT CODES:
    0    Chain is cryptographically valid and all invariants hold
    1    Integrity violation (broken hash, link, sequence, or anchor)
    2    Usage error or file not found
"#,
        env!("CARGO_PKG_VERSION")
    );
}

struct ParsedLine {
    sequence: u64,
    event_id: String,
    timestamp: String,
    event_type: String,
    actor: String,
    prev_hash: String,
    event_hash: String,
    payload_json: String,
    hash_version: Option<u64>,
}

fn compute_v1(seq: u64, id: &str, ts: &str, et: &str, actor: &str, prev: &str, payload_json: &str) -> String {
    let header = format!("{seq}:{id}:{ts}:{et}:{actor}:{prev}:");
    let mut input = Vec::with_capacity(header.len() + payload_json.len());
    input.extend_from_slice(header.as_bytes());
    input.extend_from_slice(payload_json.as_bytes());
    argus_ledger::sha256_hex(&input)
}

fn verify_parsed_events(
    events: &[ParsedLine],
    anchor: Option<(u64, &str)>,
) -> Result<(usize, usize, String, String), (u64, String)> {
    if events.is_empty() {
        return Ok((0, 0, String::new(), String::new()));
    }

    let mut expected_prev = argus_ledger::GENESIS_PREV_HASH.to_string();
    let mut v1_count = 0usize;
    let mut v2_count = 0usize;
    let root_hash = events[0].event_hash.clone();
    let head_hash = events.last().unwrap().event_hash.clone();

    for (idx, ev) in events.iter().enumerate() {
        let expected_seq = (idx as u64) + 1;
        if ev.sequence != expected_seq {
            return Err((
                ev.sequence,
                format!("Sequence discontinuity: expected {expected_seq}, found {}", ev.sequence),
            ));
        }

        if ev.prev_hash != expected_prev {
            return Err((
                ev.sequence,
                format!(
                    "Broken prev_hash link at seq {}: expected {expected_prev}, found {}",
                    ev.sequence, ev.prev_hash
                ),
            ));
        }

        let computed = if ev.hash_version == Some(2) {
            let digest = argus_ledger::compute_payload_digest(&ev.payload_json);
            argus_ledger::compute_event_hash_from_digest(
                ev.sequence,
                &ev.event_id,
                &ev.timestamp,
                &ev.event_type,
                &ev.actor,
                &ev.prev_hash,
                &digest,
            )
        } else {
            compute_v1(
                ev.sequence,
                &ev.event_id,
                &ev.timestamp,
                &ev.event_type,
                &ev.actor,
                &ev.prev_hash,
                &ev.payload_json,
            )
        };

        if computed != ev.event_hash {
            return Err((
                ev.sequence,
                format!(
                    "Event hash mismatch at seq {}: computed {computed}, recorded {}",
                    ev.sequence, ev.event_hash
                ),
            ));
        }

        if let Some((anchor_seq, anchor_hash)) = anchor {
            if ev.sequence == anchor_seq && ev.event_hash != anchor_hash {
                return Err((
                    ev.sequence,
                    format!(
                        "Anchor verification failed at seq {anchor_seq}: expected hash {anchor_hash}, found {}",
                        ev.event_hash
                    ),
                ));
            }
        }

        if ev.hash_version == Some(2) {
            v2_count += 1;
        } else {
            v1_count += 1;
        }
        expected_prev = ev.event_hash.clone();
    }

    if let Some((anchor_seq, _anchor_hash)) = anchor {
        if anchor_seq > events.len() as u64 {
            return Err((
                anchor_seq,
                format!(
                    "Anchor sequence {anchor_seq} exceeds total events in ledger ({})",
                    events.len()
                ),
            ));
        }
    }

    Ok((v1_count, v2_count, root_hash, head_hash))
}

fn load_events<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<ParsedLine>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = val.as_object() {
                let seq = match obj.get("sequence").and_then(|v| v.as_u64()) {
                    Some(s) => s,
                    None => continue,
                };
                let event_id = obj.get("event_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let timestamp = obj.get("timestamp").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let event_type = obj.get("event_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let actor = obj.get("actor").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let prev_hash = obj.get("prev_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let event_hash = obj.get("event_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let hash_version = obj.get("hash_version").and_then(|v| v.as_u64());

                let payload_json = match obj.get("payload") {
                    Some(p) => serde_json::to_string(p).unwrap_or_else(|_| "{}".to_string()),
                    None => "{}".to_string(),
                };

                events.push(ParsedLine {
                    sequence: seq,
                    event_id,
                    timestamp,
                    event_type,
                    actor,
                    prev_hash,
                    event_hash,
                    payload_json,
                    hash_version,
                });
            }
        }
    }

    Ok(events)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut ledger_path: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut benchmark_mode = false;
    let mut anchor: Option<(u64, String)> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-v" => {
                println!("argus-verify {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--json" => {
                json_mode = true;
            }
            "--benchmark" | "-b" => {
                benchmark_mode = true;
            }
            "--anchor" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("Error: --anchor requires <SEQ>:<HASH>");
                    std::process::exit(2);
                }
                let parts: Vec<&str> = args[i].splitn(2, ':').collect();
                if parts.len() != 2 {
                    eprintln!("Error: invalid anchor format. Expected <SEQ>:<HASH>");
                    std::process::exit(2);
                }
                let seq = match parts[0].parse::<u64>() {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("Error: anchor sequence must be an integer");
                        std::process::exit(2);
                    }
                };
                anchor = Some((seq, parts[1].to_string()));
            }
            other => {
                if other.starts_with('-') {
                    eprintln!("Error: unknown option '{other}'");
                    std::process::exit(2);
                } else {
                    ledger_path = Some(PathBuf::from(other));
                }
            }
        }
        i += 1;
    }

    let path = ledger_path
        .or_else(|| std::env::var("ARGUS_AUDIT_PATH").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/opt/data/runtime/argus/audit.jsonl"));

    if !path.exists() {
        if json_mode {
            println!(
                r#"{{"valid":false,"error":"file not found","path":"{}"}}"#,
                path.display()
            );
        } else {
            eprintln!("Error: audit file not found: {}", path.display());
        }
        std::process::exit(2);
    }

    let t_load = Instant::now();
    let events = match load_events(&path) {
        Ok(ev) => ev,
        Err(e) => {
            if json_mode {
                println!(
                    r#"{{"valid":false,"error":"failed to read file: {}"}}"#,
                    e
                );
            } else {
                eprintln!("Error: failed to read ledger: {e}");
            }
            std::process::exit(2);
        }
    };
    let load_ms = t_load.elapsed().as_secs_f64() * 1000.0;

    let anchor_ref = anchor.as_ref().map(|(seq, hash)| (*seq, hash.as_str()));

    if benchmark_mode {
        let iterations = 5;
        let mut times = Vec::new();
        let mut last_res = None;
        for _ in 0..iterations {
            let t0 = Instant::now();
            let res = verify_parsed_events(&events, anchor_ref);
            let elapsed = t0.elapsed();
            times.push(elapsed.as_secs_f64() * 1000.0);
            last_res = Some(res);
        }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let min_ms = times[0];
        let p50_ms = times[times.len() / 2];
        let max_ms = times[times.len() - 1];
        let total_ev = events.len();
        let ev_per_sec = (total_ev as f64) / (p50_ms / 1000.0);

        if json_mode {
            println!(
                r#"{{"benchmark":true,"iterations":{},"events":{},"p50_ms":{:.2},"min_ms":{:.2},"max_ms":{:.2},"events_per_sec":{:.0}}}"#,
                iterations, total_ev, p50_ms, min_ms, max_ms, ev_per_sec
            );
        } else {
            println!(
                "Benchmark ({} iterations over {} events):\n  p50: {:.2} ms ({:.0} ev/s)\n  min: {:.2} ms\n  max: {:.2} ms",
                iterations, total_ev, p50_ms, ev_per_sec, min_ms, max_ms
            );
        }

        match last_res.unwrap() {
            Ok(_) => std::process::exit(0),
            Err(_) => std::process::exit(1),
        }
    }

    let t_verify = Instant::now();
    let verify_res = verify_parsed_events(&events, anchor_ref);
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
    let total_ev = events.len();
    let rate = if verify_ms > 0.0 {
        (total_ev as f64) / (verify_ms / 1000.0)
    } else {
        0.0
    };

    match verify_res {
        Ok((v1_count, v2_count, root_hash, head_hash)) => {
            if json_mode {
                println!(
                    r#"{{"valid":true,"total_events":{},"v1_legacy_events":{},"v2_events":{},"root_hash":"{}","head_hash":"{}","elapsed_ms":{:.2},"load_ms":{:.2},"events_per_sec":{:.0}}}"#,
                    total_ev, v1_count, v2_count, root_hash, head_hash, verify_ms, load_ms, rate
                );
            } else {
                println!("Audit Ledger Integrity: VALID");
                println!("  Total events:  {}", total_ev);
                println!("  Format v1:     {} (legacy pre-20261015)", v1_count);
                println!("  Format v2:     {} (active domain-separated)", v2_count);
                println!("  Root hash:     {}", root_hash);
                println!("  Head hash:     {}", head_hash);
                println!("  Load time:     {:.2} ms", load_ms);
                println!("  Verify time:   {:.2} ms ({:.0} events/sec)", verify_ms, rate);
                if let Some((aseq, ahash)) = anchor {
                    println!("  Anchor (seq {}): MATCHED ({})", aseq, ahash);
                }
            }
            std::process::exit(0);
        }
        Err((failed_seq, error_msg)) => {
            if json_mode {
                println!(
                    r#"{{"valid":false,"first_broken_sequence":{},"error":"{}","elapsed_ms":{:.2}}}"#,
                    failed_seq, error_msg, verify_ms
                );
            } else {
                eprintln!("Audit Ledger Integrity: FAILED");
                eprintln!("  Broken at seq: {}", failed_seq);
                eprintln!("  Error detail:  {}", error_msg);
                eprintln!("  Time to fail:  {:.2} ms", verify_ms);
            }
            std::process::exit(1);
        }
    }
}
