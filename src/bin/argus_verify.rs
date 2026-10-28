//! `argus-verify`: standalone verifier CLI for Argus ledgers.
//!
//! The CLI is a thin front end over the library: every line is parsed by
//! [`argus_ledger::AuditEvent::from_json_line`] and the chain is checked by
//! [`argus_ledger::VerificationPolicy::verify`], so the CLI, `FileLedger::verify_chain` and the
//! Python package apply one set of rules (hash formats 1 and 2, prev_hash links, sequence
//! continuity, strictly increasing timestamps, anchors). It fails closed: a non-blank line that
//! is not a complete record is an integrity failure at that file position.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use argus_ledger::{AuditEvent, ChainAnchor, ChainVerificationReport, VerificationPolicy};

fn print_help() {
    println!(
        r#"argus-verify {} - Cryptographic ledger verifier for Argus audit trails

USAGE:
    argus-verify [OPTIONS] [LEDGER_FILE]

ARGS:
    <LEDGER_FILE>    Path to Argus audit.jsonl (default: ARGUS_AUDIT_PATH or /opt/data/runtime/argus/audit.jsonl)

OPTIONS:
    --anchor <SEQ>:<HASH>   Verify the chain witnesses a known sequence and event hash
    --benchmark, -b         Run 5 iterations (open, parse and verify) and report the median
    --json                  Output results in structured machine-readable JSON
    --help, -h              Print this help text
    --version, -v           Print version information

EXIT CODES:
    0    Chain is cryptographically valid and all invariants hold
    1    Integrity violation (malformed record, broken hash, link, sequence, timestamp or anchor)
    2    Usage error or file not found
"#,
        env!("CARGO_PKG_VERSION")
    );
}

/// Why a ledger file could not be turned into a list of events.
enum LoadError {
    /// The file could not be read at all: a usage/environment problem, exit 2.
    Io(String),
    /// A non-blank line is not a complete record: an integrity failure at `position`, exit 1.
    Malformed { position: u64, detail: String },
}

/// Parse every non-blank line or fail. A verifier that skipped what it could not read would
/// call a torn or vandalised tail "valid" while the library and Python verifiers reject it.
/// `position` counts non-blank lines, so it is the chain position the record should occupy and
/// never a value read from the record itself.
fn load_events(path: &Path) -> Result<Vec<AuditEvent>, LoadError> {
    let file = File::open(path).map_err(|e| LoadError::Io(format!("failed to read file: {e}")))?;
    let mut events = Vec::new();
    let mut position = 0u64;
    for (idx, line_res) in BufReader::new(file).lines().enumerate() {
        let line = line_res
            .map_err(|e| LoadError::Io(format!("read error at line {}: {e}", idx + 1)))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue; // blank lines only; a malformed line is never skipped
        }
        position += 1;
        let event = AuditEvent::from_json_line(trimmed).map_err(|e| LoadError::Malformed {
            position,
            detail: format!("malformed record at line {}: {e}", idx + 1),
        })?;
        events.push(event);
    }
    Ok(events)
}

/// Round to two decimals for display; the value is informational.
fn ms(d: std::time::Duration) -> f64 {
    (d.as_secs_f64() * 1000.0 * 100.0).round() / 100.0
}

/// Record content (hashes, error text) is emitted through serde_json only: hand-built JSON let
/// a crafted `prev_hash` inject `"valid":true` into the machine-readable output.
fn emit_failure(json_mode: bool, position: u64, error: &str, elapsed: std::time::Duration) {
    if json_mode {
        let out = serde_json::json!({
            "valid": false,
            "first_broken_sequence": position,
            "error": error,
            "elapsed_ms": ms(elapsed),
        });
        println!("{out}");
    } else {
        eprintln!("Audit Ledger Integrity: FAILED");
        eprintln!("  Broken at seq: {position}");
        eprintln!("  Error detail:  {error}");
        eprintln!("  Time to fail:  {:.2} ms", ms(elapsed));
    }
}

fn emit_success(
    json_mode: bool,
    report: &ChainVerificationReport,
    anchor: Option<&ChainAnchor>,
    elapsed: std::time::Duration,
) {
    let total = report.total_events;
    let v1 = report.legacy_events;
    let v2 = total - v1;
    let rate = if elapsed.as_secs_f64() > 0.0 {
        (total as f64 / elapsed.as_secs_f64()).round()
    } else {
        0.0
    };
    if json_mode {
        let out = serde_json::json!({
            "valid": true,
            "total_events": total,
            "v1_legacy_events": v1,
            "v2_events": v2,
            "root_hash": report.root_hash,
            "head_hash": report.head_hash,
            "elapsed_ms": ms(elapsed),
            "events_per_sec": rate,
        });
        println!("{out}");
    } else {
        println!("Audit Ledger Integrity: VALID");
        println!("  Total events:  {total}");
        println!("  Format v1:     {v1} (legacy pre-20261015)");
        println!("  Format v2:     {v2} (active domain-separated)");
        println!("  Root hash:     {}", report.root_hash);
        println!("  Head hash:     {}", report.head_hash);
        println!(
            "  Elapsed:       {:.2} ms end to end, open+parse+verify ({rate:.0} events/sec)",
            ms(elapsed)
        );
        if let Some(a) = anchor {
            println!("  Anchor (seq {}): MATCHED ({})", a.sequence, a.event_hash);
        }
    }
}

/// Why one pass did not end in a valid chain.
enum Failure {
    /// Integrity verdict: exit 1, reported at a chain position.
    Integrity(u64, String),
    /// The file could not be read: exit 2, no verdict.
    Io(String),
}

/// One end-to-end pass: open, parse and verify.
fn run_once(path: &Path, policy: &VerificationPolicy) -> Result<ChainVerificationReport, Failure> {
    let events = match load_events(path) {
        Ok(events) => events,
        Err(LoadError::Malformed { position, detail }) => {
            return Err(Failure::Integrity(position, detail))
        }
        Err(LoadError::Io(detail)) => return Err(Failure::Io(detail)),
    };
    match policy.verify(&events) {
        Ok(report) if report.valid => Ok(report),
        Ok(report) => Err(Failure::Integrity(
            report.first_broken_sequence.unwrap_or(0),
            report.error_detail.unwrap_or_else(|| "verification failed".into()),
        )),
        Err(e) => Err(Failure::Io(e.to_string())),
    }
}

fn exit_io(json_mode: bool, detail: &str) -> ! {
    if json_mode {
        let out = serde_json::json!({ "valid": false, "error": detail });
        println!("{out}");
    } else {
        eprintln!("Error: failed to read ledger: {detail}");
    }
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut ledger_path: Option<PathBuf> = None;
    let mut json_mode = false;
    let mut benchmark_mode = false;
    let mut anchor: Option<ChainAnchor> = None;

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
                let sequence = match parts[0].parse::<u64>() {
                    Ok(s) => s,
                    Err(_) => {
                        eprintln!("Error: anchor sequence must be an integer");
                        std::process::exit(2);
                    }
                };
                anchor = Some(ChainAnchor {
                    sequence,
                    event_hash: parts[1].to_string(),
                });
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
            let out = serde_json::json!({
                "valid": false,
                "error": "file not found",
                "path": path.display().to_string(),
            });
            println!("{out}");
        } else {
            eprintln!("Error: audit file not found: {}", path.display());
        }
        std::process::exit(2);
    }

    // The CLI has no key input yet, so signatures are not checked here; the library does when
    // `verifying_key` is set.
    let policy = VerificationPolicy {
        anchor: anchor.clone(),
        verifying_key: None,
    };

    if benchmark_mode {
        // Each iteration is a complete open+parse+verify pass, which is what an operator pays
        // for; a verify-only loop over pre-parsed events overstated throughput by 3-4x.
        let iterations = 5;
        let mut times = Vec::with_capacity(iterations);
        let mut last = None;
        for _ in 0..iterations {
            let t0 = Instant::now();
            let res = run_once(&path, &policy);
            times.push(t0.elapsed());
            last = Some(res);
        }
        times.sort();
        let p50 = times[times.len() / 2];
        let (total, valid) = match last.as_ref().unwrap() {
            Ok(report) => (report.total_events, true),
            Err(Failure::Integrity(..)) => (0, false),
            Err(Failure::Io(detail)) => exit_io(json_mode, detail),
        };
        let ev_per_sec = if p50.as_secs_f64() > 0.0 {
            (total as f64 / p50.as_secs_f64()).round()
        } else {
            0.0
        };
        if json_mode {
            let out = serde_json::json!({
                "benchmark": true,
                "valid": valid,
                "iterations": iterations,
                "events": total,
                "p50_ms": ms(p50),
                "min_ms": ms(times[0]),
                "max_ms": ms(times[times.len() - 1]),
                "events_per_sec": ev_per_sec,
                "measures": "open+parse+verify",
            });
            println!("{out}");
        } else {
            println!(
                "Benchmark ({iterations} iterations, open+parse+verify, {total} events):\n  p50: {:.2} ms ({ev_per_sec:.0} ev/s)\n  min: {:.2} ms\n  max: {:.2} ms",
                ms(p50),
                ms(times[0]),
                ms(times[times.len() - 1])
            );
        }
        std::process::exit(if valid { 0 } else { 1 });
    }

    let t0 = Instant::now();
    let result = run_once(&path, &policy);
    let elapsed = t0.elapsed();
    match result {
        Ok(report) => {
            emit_success(json_mode, &report, anchor.as_ref(), elapsed);
            std::process::exit(0);
        }
        Err(Failure::Integrity(position, error)) => {
            emit_failure(json_mode, position, &error, elapsed);
            std::process::exit(1);
        }
        Err(Failure::Io(detail)) => exit_io(json_mode, &detail),
    }
}
