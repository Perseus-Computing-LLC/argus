//! Python extension over the `argus-ledger` verifier (issue #15).
//!
//! `verify_lines` feeds non-blank ledger lines, in file order, through the same
//! [`ChainVerifier`] that `FileLedger::verify_chain` and `argus-verify` use. A line that does
//! not parse fails the chain at the position it would have occupied, exactly as
//! `VerificationPolicy::verify_stream` treats an `Err` record. The Python package owns file
//! access and locking; this module owns the verdict.

use argus_ledger::{AuditEvent, ChainAnchor, ChainVerificationReport, ChainVerifier, LedgerError, VerificationPolicy};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Stable, language-neutral name for the failure class, so the Python wrapper can phrase the
/// parse case the way its own loop always has without parsing an error string.
fn failure_kind(parse_failure: bool, failure: Option<&LedgerError>) -> Option<&'static str> {
    if parse_failure {
        return Some("parse");
    }
    failure.map(|error| match error {
        LedgerError::SequenceDiscontinuity(_) => "sequence",
        LedgerError::HashMismatch(_) => "hash",
        LedgerError::InvalidTimestamp(_) => "timestamp",
        LedgerError::InvalidSignature(_) => "signature",
        LedgerError::InvalidInput(_) => "input",
        LedgerError::LockError(_) => "lock",
        _ => "other",
    })
}

fn report_to_dict<'py>(
    py: Python<'py>,
    report: &ChainVerificationReport,
    parse_failure: bool,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    out.set_item("valid", report.valid)?;
    out.set_item("total_events", report.total_events)?;
    out.set_item("root_hash", &report.root_hash)?;
    out.set_item("head_hash", &report.head_hash)?;
    out.set_item("first_broken_sequence", report.first_broken_sequence)?;
    out.set_item("error_detail", report.error_detail.as_deref())?;
    out.set_item("failure_kind", failure_kind(parse_failure, report.failure.as_ref()))?;
    out.set_item("legacy_events", report.legacy_events)?;
    out.set_item("legacy_timestamp_regressions", report.legacy_timestamp_regressions)?;
    out.set_item("warnings", PyList::new(py, &report.warnings)?)?;
    Ok(out)
}

/// Verify an iterable of ledger lines (each one JSON record, blanks already removed).
///
/// `anchor` is `(sequence, event_hash)`; `verifying_key` is a raw 32-byte Ed25519 public key;
/// `legacy_timestamps_before` is the accept-as-historic cutoff (issue #14), already validated
/// by the caller to be `>= 1` or `None`. Returns a dict with the `ChainVerificationReport`
/// fields plus `failure_kind`.
#[pyfunction]
#[pyo3(signature = (lines, *, anchor=None, verifying_key=None, legacy_timestamps_before=None))]
fn verify_lines<'py>(
    py: Python<'py>,
    lines: &Bound<'py, PyAny>,
    anchor: Option<(u64, String)>,
    verifying_key: Option<Vec<u8>>,
    legacy_timestamps_before: Option<u64>,
) -> PyResult<Bound<'py, PyDict>> {
    if legacy_timestamps_before == Some(0) {
        return Err(PyValueError::new_err("legacy_timestamps_before must be >= 1"));
    }
    let verifying_key = match verifying_key {
        None => None,
        Some(bytes) => {
            let raw: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| PyValueError::new_err("verifying_key must be a 32-byte Ed25519 public key"))?;
            Some(
                ed25519_dalek::VerifyingKey::from_bytes(&raw)
                    .map_err(|e| PyValueError::new_err(format!("verifying_key is not a valid Ed25519 key: {e}")))?,
            )
        }
    };
    let policy = VerificationPolicy {
        anchor: anchor.map(|(sequence, event_hash)| ChainAnchor { sequence, event_hash }),
        anchors: Vec::new(),
        verifying_key,
        legacy_timestamps_before,
    };
    let mut verifier = ChainVerifier::new(&policy);
    for item in lines.try_iter()? {
        let line: String = item?.extract()?;
        match AuditEvent::from_json_line(&line) {
            Ok(event) => {
                if let Some(report) = verifier.push(&event) {
                    return report_to_dict(py, &report, false);
                }
            }
            Err(error) => {
                let report = verifier.fail_next(error);
                return report_to_dict(py, &report, true);
            }
        }
    }
    report_to_dict(py, &verifier.finish(), false)
}

/// Parse one record with the Rust fail-closed parser and re-serialise it with
/// `AuditEvent::to_json_line`. Raises `ValueError` for a line the verifier would reject.
#[pyfunction]
fn canonical_json_line(line: &str) -> PyResult<String> {
    AuditEvent::from_json_line(line)
        .map(|event| event.to_json_line())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Version of the Rust crate this extension was built from.
#[pyfunction]
fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn argus_ledger_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_lines, m)?)?;
    m.add_function(wrap_pyfunction!(canonical_json_line, m)?)?;
    m.add_function(wrap_pyfunction!(crate_version, m)?)?;
    Ok(())
}
