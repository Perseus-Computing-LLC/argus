//! # argus-ledger
//!
//! Tamper-evident append-only SHA-256 provenance and audit ledger for autonomous agents.
//!
//! When autonomous agents execute commands, invoke external APIs, or mutate persistent
//! memory, post-incident investigations require cryptographic certainty regarding what
//! actions occurred and in what sequence. Standard application logs can be rewritten,
//! reordered, or truncated.
//!
//! Argus provides an immutable append-only hash chain where each event records:
//!
//! 1. A strictly sequential sequence integer.
//! 2. A cryptographic digest binding the payload to the previous event's hash (`prev_hash`).
//! 3. Deterministic chain verification that validates integrity in linear time.
//!
//! ## Architecture Overview
//!
//! - [`AuditEvent`]: The individual structured log record containing event metadata,
//!   payload, monotonic sequence number, and SHA-256 digests.
//! - [`ChainVerificationReport`]: Audit summary produced by traversing the hash chain
//!   from genesis to head, validating sequence ordering and hash consistency.
//! - [`AuditLedgerWriter`]: Trait for appending new events to the audit log.
//! - [`AuditLedgerReader`]: Trait for querying events by sequence or reading the chain head.
//! - [`AuditVerifier`]: Trait for verifying cryptographic integrity across the chain.
//! - [`InMemoryLedger`]: Thread-safe reference ledger implementation.
//!
//! ## Quick Start
//!
//! ```rust
//! use argus_ledger::{AuditLedgerReader, AuditLedgerWriter, AuditVerifier, InMemoryLedger, GENESIS_PREV_HASH};
//!
//! // Create an in-memory audit ledger
//! let mut ledger = InMemoryLedger::new();
//!
//! // 1. Record an initial initialization event
//! let ev1 = ledger.append("agent.startup", "coordinator", "{\"status\":\"initialized\"}")
//!     .expect("First event must succeed");
//! assert_eq!(ev1.sequence, 1);
//! assert_eq!(ev1.prev_hash, GENESIS_PREV_HASH);
//!
//! // 2. Record a tool call event cryptographically chained to ev1
//! let ev2 = ledger.append("tool.exec", "worker_1", "{\"command\":\"build\"}")
//!     .expect("Second event must succeed");
//! assert_eq!(ev2.sequence, 2);
//! assert_eq!(ev2.prev_hash, ev1.event_hash);
//!
//! // 3. Verify cryptographic chain integrity
//! let report = ledger.verify_chain().expect("Verification must complete");
//! assert!(report.valid);
//! assert_eq!(report.total_events, 2);
//! assert_eq!(report.head_hash, ev2.event_hash);
//! ```

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The fixed 64-character hexadecimal previous hash for genesis events.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// An immutable event record committed to the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Monotonically increasing sequence number starting at 1.
    pub sequence: u64,
    /// Unique event identifier string.
    pub event_id: String,
    /// Event timestamp in seconds since UNIX epoch.
    pub timestamp: String,
    /// Dot-separated action taxonomy (for example: agent.startup, tool.exec).
    pub event_type: String,
    /// Process, user, or subagent identity that triggered the action.
    pub actor: String,
    /// Canonical JSON payload representing the event inputs and parameters.
    pub payload: String,
    /// The event_hash of sequence - 1, or GENESIS_PREV_HASH for sequence 1.
    pub prev_hash: String,
    /// SHA-256 hexadecimal hash computed across the event header and payload.
    pub event_hash: String,
    /// Optional detached cryptographic signature verifying author authenticity.
    pub signature: Option<String>,
}

/// Cryptographic integrity verification report for an event chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainVerificationReport {
    /// True if all sequence numbers, previous hashes, and event hashes match expectations.
    pub valid: bool,
    /// Total count of events verified in the ledger.
    pub total_events: usize,
    /// Event hash of the genesis event (sequence 1).
    pub root_hash: String,
    /// Event hash of the most recent event in the ledger.
    pub head_hash: String,
    /// Sequence number of the first detected discrepancy, or None if valid.
    pub first_broken_sequence: Option<u64>,
    /// Human-readable explanation of detected tampering or discontinuity.
    pub error_detail: Option<String>,
    /// Timestamp when verification was completed in seconds since UNIX epoch.
    pub checked_at: String,
}

/// Errors returned during ledger append, retrieval, or verification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// Event sequence numbers are missing or out of order.
    SequenceDiscontinuity(String),
    /// Computed event hash does not match recorded event hash.
    HashMismatch(String),
    /// Mutex lock contention or thread synchronization failure.
    LockError(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceDiscontinuity(msg) => write!(f, "Sequence discontinuity: {}", msg),
            Self::HashMismatch(msg) => write!(f, "Hash mismatch: {}", msg),
            Self::LockError(msg) => write!(f, "Lock error: {}", msg),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Trait defining append operations for audit ledgers.
pub trait AuditLedgerWriter: Send + Sync {
    /// Cryptographically append a new action record to the ledger.
    fn append(
        &mut self,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<AuditEvent, LedgerError>;
}

/// Trait defining read and query operations for audit ledgers.
pub trait AuditLedgerReader: Send + Sync {
    /// Fetch an individual event by its 1-indexed sequence number.
    fn get_event(&self, sequence: u64) -> Result<Option<AuditEvent>, LedgerError>;
    /// Retrieve the most recently committed event from the head of the chain.
    fn head(&self) -> Result<Option<AuditEvent>, LedgerError>;
    /// Return an in-order snapshot of all events committed to the ledger.
    fn all_events(&self) -> Result<Vec<AuditEvent>, LedgerError>;
}

/// Trait defining full-chain cryptographic audit verification.
pub trait AuditVerifier: Send + Sync {
    /// Traverse the ledger from genesis to head, verifying all hashes and sequence numbers.
    fn verify_chain(&self) -> Result<ChainVerificationReport, LedgerError>;
}

/// Standalone, pure-Rust SHA-256 implementation (FIPS 180-4 compliant, zero external dependencies).
pub fn sha256_hex(input: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    let mut result = String::with_capacity(64);
    for val in h {
        result.push_str(&format!("{:08x}", val));
    }
    result
}

/// Compute the canonical SHA-256 event hash across all event metadata and payload fields.
pub fn compute_event_hash(
    sequence: u64,
    event_id: &str,
    timestamp: &str,
    event_type: &str,
    actor: &str,
    prev_hash: &str,
    payload: &str,
) -> String {
    let header = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        sequence, event_id, timestamp, event_type, actor, prev_hash, payload
    );
    sha256_hex(header.as_bytes())
}

/// Thread-safe in-memory reference implementation of an append-only audit ledger.
#[derive(Default, Clone)]
pub struct InMemoryLedger {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

impl InMemoryLedger {
    /// Construct a new empty in-memory audit ledger.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditLedgerWriter for InMemoryLedger {
    fn append(
        &mut self,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<AuditEvent, LedgerError> {
        let mut store = self
            .events
            .lock()
            .map_err(|e| LedgerError::LockError(e.to_string()))?;
        let sequence = (store.len() as u64) + 1;
        let prev_hash = if let Some(last) = store.last() {
            last.event_hash.clone()
        } else {
            GENESIS_PREV_HASH.to_string()
        };

        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp = format!("{}", now_sec);
        let event_id = format!("ev_{}_{}", sequence, now_sec);

        let event_hash = compute_event_hash(
            sequence, &event_id, &timestamp, event_type, actor, &prev_hash, payload,
        );

        let event = AuditEvent {
            sequence,
            event_id,
            timestamp,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            payload: payload.to_string(),
            prev_hash,
            event_hash,
            signature: None,
        };

        store.push(event.clone());
        Ok(event)
    }
}

impl AuditLedgerReader for InMemoryLedger {
    fn get_event(&self, sequence: u64) -> Result<Option<AuditEvent>, LedgerError> {
        let store = self
            .events
            .lock()
            .map_err(|e| LedgerError::LockError(e.to_string()))?;
        if sequence == 0 || sequence > (store.len() as u64) {
            Ok(None)
        } else {
            Ok(Some(store[(sequence - 1) as usize].clone()))
        }
    }

    fn head(&self) -> Result<Option<AuditEvent>, LedgerError> {
        let store = self
            .events
            .lock()
            .map_err(|e| LedgerError::LockError(e.to_string()))?;
        Ok(store.last().cloned())
    }

    fn all_events(&self) -> Result<Vec<AuditEvent>, LedgerError> {
        let store = self
            .events
            .lock()
            .map_err(|e| LedgerError::LockError(e.to_string()))?;
        Ok(store.clone())
    }
}

impl AuditVerifier for InMemoryLedger {
    fn verify_chain(&self) -> Result<ChainVerificationReport, LedgerError> {
        let store = self
            .events
            .lock()
            .map_err(|e| LedgerError::LockError(e.to_string()))?;
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let checked_at = format!("{}", now_sec);

        if store.is_empty() {
            return Ok(ChainVerificationReport {
                valid: true,
                total_events: 0,
                root_hash: String::new(),
                head_hash: String::new(),
                first_broken_sequence: None,
                error_detail: None,
                checked_at,
            });
        }

        let mut expected_prev = GENESIS_PREV_HASH.to_string();
        for (idx, event) in store.iter().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if event.sequence != expected_seq {
                return Ok(ChainVerificationReport {
                    valid: false,
                    total_events: store.len(),
                    root_hash: store[0].event_hash.clone(),
                    head_hash: store.last().unwrap().event_hash.clone(),
                    first_broken_sequence: Some(event.sequence),
                    error_detail: Some(format!("Discontinuous sequence at index {}", idx)),
                    checked_at,
                });
            }

            if event.prev_hash != expected_prev {
                return Ok(ChainVerificationReport {
                    valid: false,
                    total_events: store.len(),
                    root_hash: store[0].event_hash.clone(),
                    head_hash: store.last().unwrap().event_hash.clone(),
                    first_broken_sequence: Some(event.sequence),
                    error_detail: Some(format!(
                        "Broken prev_hash chain at sequence {}",
                        event.sequence
                    )),
                    checked_at,
                });
            }

            let expected_hash = compute_event_hash(
                event.sequence,
                &event.event_id,
                &event.timestamp,
                &event.event_type,
                &event.actor,
                &event.prev_hash,
                &event.payload,
            );

            if event.event_hash != expected_hash {
                return Ok(ChainVerificationReport {
                    valid: false,
                    total_events: store.len(),
                    root_hash: store[0].event_hash.clone(),
                    head_hash: store.last().unwrap().event_hash.clone(),
                    first_broken_sequence: Some(event.sequence),
                    error_detail: Some(format!(
                        "Tampered content hash at sequence {}",
                        event.sequence
                    )),
                    checked_at,
                });
            }

            expected_prev = event.event_hash.clone();
        }

        Ok(ChainVerificationReport {
            valid: true,
            total_events: store.len(),
            root_hash: store[0].event_hash.clone(),
            head_hash: store.last().unwrap().event_hash.clone(),
            first_broken_sequence: None,
            error_detail: None,
            checked_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_append_and_verify_chain() {
        let mut ledger = InMemoryLedger::new();
        let ev1 = ledger
            .append("agent.init", "hermes", "{\"state\":\"ready\"}")
            .unwrap();
        assert_eq!(ev1.sequence, 1);
        assert_eq!(ev1.prev_hash, GENESIS_PREV_HASH);

        let ev2 = ledger
            .append("tool.call", "hermes", "{\"tool\":\"kibisis\"}")
            .unwrap();
        assert_eq!(ev2.sequence, 2);
        assert_eq!(ev2.prev_hash, ev1.event_hash);

        let report = ledger.verify_chain().unwrap();
        assert!(report.valid);
        assert_eq!(report.total_events, 2);
        assert_eq!(report.head_hash, ev2.event_hash);
    }
}
