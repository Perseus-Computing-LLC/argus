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
//! let ledger = InMemoryLedger::new();
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

use sha2::{Digest, Sha256};
use std::borrow::Borrow;
use std::sync::{Arc, Mutex, MutexGuard};
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
    /// `ev_{ledger_id}_{sequence}`, where `ledger_id` is the ledger's random 128-bit identity.
    pub event_id: String,
    /// Nanoseconds since the UNIX epoch; strictly increasing along the chain.
    pub timestamp: String,
    /// Dot-separated action taxonomy (for example: agent.startup, tool.exec).
    pub event_type: String,
    /// Process, user, or subagent identity that triggered the action.
    pub actor: String,
    /// Canonical JSON object (see [`validate_canonical_payload`]): event inputs and parameters.
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
#[must_use = "tampering is reported as `Ok` with `valid == false`; call `ensure_valid()`"]
pub struct ChainVerificationReport {
    /// True if all sequence numbers, previous hashes, and event hashes match expectations.
    pub valid: bool,
    /// Total count of events verified in the ledger.
    pub total_events: usize,
    /// Event hash of the genesis event (sequence 1).
    pub root_hash: String,
    /// Event hash of the most recent event in the ledger.
    pub head_hash: String,
    /// 1-based chain position of the first discrepancy (never a value read from the record).
    pub first_broken_sequence: Option<u64>,
    /// Human-readable explanation of detected tampering or discontinuity.
    pub error_detail: Option<String>,
    /// Typed failure, or None if valid.
    pub failure: Option<LedgerError>,
    /// Timestamp when verification was completed in seconds since UNIX epoch.
    pub checked_at: String,
}

/// Externally witnessed commitment to one chain position, such as a head published to a
/// transparency log or held by another trust domain. It is evidence only if the ledger's writer
/// cannot rewrite the place it was obtained from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainAnchor {
    /// Sequence number of the witnessed event.
    pub sequence: u64,
    /// `event_hash` of the witnessed event.
    pub event_hash: String,
}

/// Trust inputs that the chain under verification cannot supply for itself.
#[derive(Debug, Clone, Default)]
pub struct VerificationPolicy {
    /// If set, the chain must contain this event unchanged. Detects rollback, truncation below
    /// the anchor, and recomputed history; events appended after it remain unwitnessed.
    pub anchor: Option<ChainAnchor>,
    /// If set, every event must carry a valid signature by this key; missing, stripped, or
    /// foreign signatures fail verification.
    pub verifying_key: Option<ed25519_dalek::VerifyingKey>,
}

impl AuditEvent {
    /// Commitment to this event's chain position, for publication to an external witness.
    pub fn anchor(&self) -> ChainAnchor {
        ChainAnchor {
            sequence: self.sequence,
            event_hash: self.event_hash.clone(),
        }
    }
}

impl ChainVerificationReport {
    /// Fail closed: `Ok(self)` only if verification passed, otherwise the typed failure.
    pub fn ensure_valid(self) -> Result<Self, LedgerError> {
        if self.valid {
            return Ok(self);
        }
        let detail = self.error_detail.unwrap_or_default();
        Err(self.failure.unwrap_or(LedgerError::HashMismatch(detail)))
    }
}

/// Errors returned during ledger append, retrieval, or verification operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    /// Event sequence numbers are missing or out of order.
    SequenceDiscontinuity(String),
    /// Computed event hash does not match recorded event hash.
    HashMismatch(String),
    /// Lock failure in other backends; `InMemoryLedger` recovers poisoned locks instead.
    LockError(String),
    /// `append` input rejected before anything was recorded.
    InvalidInput(String),
    /// A required event signature is missing or does not verify.
    InvalidSignature(String),
    /// The host clock is unusable, or a recorded timestamp is malformed or out of order.
    InvalidTimestamp(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SequenceDiscontinuity(msg) => write!(f, "Sequence discontinuity: {}", msg),
            Self::HashMismatch(msg) => write!(f, "Hash mismatch: {}", msg),
            Self::LockError(msg) => write!(f, "Lock error: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            Self::InvalidTimestamp(msg) => write!(f, "Invalid timestamp: {}", msg),
        }
    }
}

impl std::error::Error for LedgerError {}

/// Trait defining append operations for audit ledgers.
pub trait AuditLedgerWriter: Send + Sync {
    /// Cryptographically append a new action record to the ledger. Implementations are
    /// internally synchronized, so one ledger can be shared across threads (e.g. in an `Arc`).
    fn append(
        &self,
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
    /// Internal consistency only: an empty, truncated, or recomputed chain passes. Tamper
    /// evidence requires [`AuditVerifier::verify_chain_with`] and an anchor.
    fn verify_chain(&self) -> Result<ChainVerificationReport, LedgerError> {
        self.verify_chain_with(&VerificationPolicy::default())
    }

    /// Traverse the ledger from genesis to head, verifying all hashes and sequence numbers
    /// against the externally supplied trust inputs in `policy`.
    fn verify_chain_with(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<ChainVerificationReport, LedgerError>;
}

/// SHA-256 (FIPS 180-4) as lowercase hex, via RustCrypto `sha2`, which `ed25519-dalek` already
/// links: streaming, no copy of the input, SHA-NI/ARMv8 accelerated where available.
pub fn sha256_hex(input: &[u8]) -> String {
    hex_string(digest_hex(&Sha256::digest(input).into()))
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_lower(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(2 * bytes.len());
    for &b in bytes {
        hex.push(char::from(HEX_DIGITS[usize::from(b >> 4)]));
        hex.push(char::from(HEX_DIGITS[usize::from(b & 0x0f)]));
    }
    hex
}

/// Lowercase hex of a SHA-256 digest, built on the stack.
fn digest_hex(digest: &[u8; 32]) -> [u8; 64] {
    let mut hex = [0u8; 64];
    for (pair, &b) in hex.chunks_exact_mut(2).zip(digest) {
        pair[0] = HEX_DIGITS[usize::from(b >> 4)];
        pair[1] = HEX_DIGITS[usize::from(b & 0x0f)];
    }
    hex
}

fn hex_string(hex: [u8; 64]) -> String {
    hex.iter().map(|&b| char::from(b)).collect()
}

/// Domain tag prepended to the event hash before signing, so an Argus signature can neither be
/// replayed into nor produced by another protocol that uses the same key.
const SIGNATURE_DOMAIN: &[u8] = b"argus.event.sig.v1\0";

/// Sign an event hash using Ed25519 asymmetric cryptography.
pub fn sign_event_hash_ed25519(event_hash: &str, private_key_bytes: &[u8; 32]) -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key_bytes);
    sign_event_hash(&signing_key, event_hash)
}

/// Sign an event hash with an existing Ed25519 signing key.
pub fn sign_event_hash(signing_key: &ed25519_dalek::SigningKey, event_hash: &str) -> String {
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(&[SIGNATURE_DOMAIN, event_hash.as_bytes()].concat());
    let mut encoded = String::with_capacity(8 + 2 * ed25519_dalek::SIGNATURE_LENGTH);
    encoded.push_str("ed25519:");
    encoded.push_str(&hex_lower(&signature.to_bytes()));
    encoded
}

/// Verify an event-hash signature. Only the lowercase-hex `ed25519:` encoding is accepted, and
/// verification is strict (`verify_strict` rejects small-order public keys and `R` points).
pub fn verify_event_hash_ed25519(
    event_hash: &str,
    signature_hex: &str,
    public_key_bytes: &[u8; 32],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Some(sig_bytes) = signature_hex
        .strip_prefix("ed25519:")
        .and_then(decode_lower_hex::<64>)
    else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key_bytes) else {
        return false;
    };
    let message = [SIGNATURE_DOMAIN, event_hash.as_bytes()].concat();
    verifying_key
        .verify_strict(&message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// Decode exactly `N` bytes of lowercase hex. Uppercase digits, signs, and every other byte are
/// rejected, so each signature has exactly one accepted string form.
fn decode_lower_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let bytes = hex.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// Domain tag for event-hash preimages (hash format v2).
const EVENT_HASH_DOMAIN: &[u8] = b"argus.event.v2\0";
/// Domain tag for payload digests (hash format v2).
const PAYLOAD_HASH_DOMAIN: &[u8] = b"argus.payload.v2\0";

/// SHA-256 of `payload` under its own domain tag; event hashes commit to this digest.
pub fn compute_payload_digest(payload: &str) -> String {
    hex_string(payload_digest_hex(payload))
}

fn payload_digest_hex(payload: &str) -> [u8; 64] {
    let mut hasher = Sha256::new_with_prefix(PAYLOAD_HASH_DOMAIN);
    hasher.update(payload);
    digest_hex(&hasher.finalize().into())
}

/// Compute the SHA-256 event hash over an injective encoding: a domain tag, the big-endian
/// sequence, then each variable-length field prefixed by its big-endian u64 byte length, the
/// last field being the payload digest.
pub fn compute_event_hash(
    sequence: u64,
    event_id: &str,
    timestamp: &str,
    event_type: &str,
    actor: &str,
    prev_hash: &str,
    payload: &str,
) -> String {
    let digest = payload_digest_hex(payload);
    hex_string(event_hash_hex(
        sequence, event_id, timestamp, event_type, actor, prev_hash, &digest,
    ))
}

/// [`compute_event_hash`] for a precomputed [`compute_payload_digest`]: O(header) work.
pub fn compute_event_hash_from_digest(
    sequence: u64,
    event_id: &str,
    timestamp: &str,
    event_type: &str,
    actor: &str,
    prev_hash: &str,
    digest: &str,
) -> String {
    hex_string(event_hash_hex(
        sequence,
        event_id,
        timestamp,
        event_type,
        actor,
        prev_hash,
        digest.as_bytes(),
    ))
}

/// The v2 event hash as lowercase hex on the stack: no heap allocation per event.
fn event_hash_hex(
    sequence: u64,
    event_id: &str,
    timestamp: &str,
    event_type: &str,
    actor: &str,
    prev_hash: &str,
    digest: &[u8],
) -> [u8; 64] {
    let mut hasher = Sha256::new_with_prefix(EVENT_HASH_DOMAIN);
    hasher.update(sequence.to_be_bytes());
    let fields = [
        event_id.as_bytes(),
        timestamp.as_bytes(),
        event_type.as_bytes(),
        actor.as_bytes(),
        prev_hash.as_bytes(),
        digest,
    ];
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    digest_hex(&hasher.finalize().into())
}

/// Largest `payload` accepted by `append`, bounding per-event memory and hashing work.
pub const MAX_PAYLOAD_BYTES: usize = 1 << 20;
/// Largest `event_type` or `actor` accepted by `append`.
pub const MAX_IDENTIFIER_BYTES: usize = 256;

/// `event_type`: dot-separated `[a-z0-9_-]+` segments. `actor`: printable ASCII without
/// whitespace, which rules out control characters, log-line injection, and Unicode homoglyphs.
fn validate_identifiers(event_type: &str, actor: &str) -> Result<(), LedgerError> {
    let type_byte = |b: u8| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-');
    let segment = |s: &str| !s.is_empty() && s.bytes().all(type_byte);
    if event_type.len() > MAX_IDENTIFIER_BYTES || !event_type.split('.').all(segment) {
        let detail = "event_type must be dot-separated [a-z0-9_-]+ segments";
        return Err(LedgerError::InvalidInput(detail.into()));
    }
    if actor.is_empty()
        || actor.len() > MAX_IDENTIFIER_BYTES
        || !actor.bytes().all(|b| b.is_ascii_graphic())
    {
        let detail = "actor must be printable ASCII without whitespace";
        return Err(LedgerError::InvalidInput(detail.into()));
    }
    Ok(())
}

/// Largest integer magnitude exactly representable as an IEEE-754 double (RFC 7493 I-JSON).
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Accept only a payload already in canonical form: a JSON object, compact, keys sorted by code
/// point, no duplicate keys or redundant escapes, and integers within +/-(2^53 - 1) as the only
/// numbers. Those bytes equal `argus_ledger.canonical` output (`sort_keys`, compact separators,
/// `ensure_ascii=False`) and RFC 8785 output, except for object keys that mix U+E000..=U+FFFF
/// with non-BMP characters (code-point versus UTF-16 key order).
pub fn validate_canonical_payload(payload: &str) -> Result<(), LedgerError> {
    // Key order and integer spelling are checked here, not inherited from `serde_json::Map` and
    // `Number`: any crate in the build can enable serde_json's `preserve_order` (maps keep
    // insertion order) or `arbitrary_precision` (numbers keep their source text, e.g. `-0`).
    fn canonical(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Number(n) => n.as_i64().is_some_and(|v| {
                v.unsigned_abs() <= MAX_SAFE_INTEGER && *n == serde_json::Number::from(v)
            }),
            serde_json::Value::Array(items) => items.iter().all(canonical),
            serde_json::Value::Object(map) => {
                map.keys().zip(map.keys().skip(1)).all(|(a, b)| a < b)
                    && map.values().all(canonical)
            }
            _ => true,
        }
    }
    let invalid = |reason: &str| LedgerError::InvalidInput(format!("payload {reason}"));
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| invalid("is not valid JSON"))?;
    if !value.is_object() || !canonical(&value) {
        return Err(invalid("must be a sorted-key object with safe integers"));
    }
    // Re-serialize into a comparing sink rather than a second O(payload) buffer.
    let mut sink = MatchesWriter {
        expected: payload.as_bytes(),
        matches: true,
    };
    let serialized = serde_json::to_writer(&mut sink, &value).is_ok();
    if !(serialized && sink.matches && sink.expected.is_empty()) {
        return Err(invalid("is not in canonical form"));
    }
    Ok(())
}

/// `io::Write` sink that checks the bytes written to it against `expected` without storing them.
struct MatchesWriter<'a> {
    /// The suffix of the expected output not yet matched.
    expected: &'a [u8],
    matches: bool,
}

impl std::io::Write for MatchesWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.matches {
            match self.expected.strip_prefix(buf) {
                Some(rest) => self.expected = rest,
                None => self.matches = false,
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parse a decimal `u64` in canonical form (no sign, no leading zeros).
fn parse_canonical_u64(s: &str) -> Option<u64> {
    let canonical = s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    canonical.then(|| s.parse().ok()).flatten()
}

/// Thread-safe in-memory reference implementation of an append-only audit ledger.
#[derive(Clone)]
pub struct InMemoryLedger {
    events: Arc<Mutex<Vec<Arc<AuditEvent>>>>,
    signing_key: Option<Arc<ed25519_dalek::SigningKey>>,
    /// Random per-instance identity bound into every `event_id`, so two ledgers (or one ledger
    /// across a restart) never produce interchangeable events.
    ledger_id: Arc<str>,
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        let mut id = [0u8; 16];
        getrandom::getrandom(&mut id).expect("OS RNG unavailable; cannot derive a ledger identity");
        let ledger_id = hex_lower(&id);
        Self {
            events: Arc::default(),
            signing_key: None,
            ledger_id: ledger_id.into(),
        }
    }
}

impl InMemoryLedger {
    /// Construct a new empty in-memory audit ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a ledger that signs the hash of every event it appends.
    pub fn with_signing_key(signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            signing_key: Some(Arc::new(signing_key)),
            ..Self::default()
        }
    }

    /// Lock the store, recovering from poisoning. Sound because the only mutation is one
    /// `Vec::push` of a fully built event, so a panic cannot leave a partial write behind.
    fn store(&self) -> MutexGuard<'_, Vec<Arc<AuditEvent>>> {
        self.events.lock().unwrap_or_else(|poisoned| {
            self.events.clear_poison();
            poisoned.into_inner()
        })
    }

    /// O(n) pointer copy under the lock; all O(bytes) work happens after it is released.
    fn snapshot(&self) -> Result<Vec<Arc<AuditEvent>>, LedgerError> {
        let store = self.store();
        Ok(store.clone())
    }
}

impl AuditLedgerWriter for InMemoryLedger {
    fn append(
        &self,
        event_type: &str,
        actor: &str,
        payload: &str,
    ) -> Result<AuditEvent, LedgerError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            let detail = format!("payload exceeds {MAX_PAYLOAD_BYTES} bytes");
            return Err(LedgerError::InvalidInput(detail));
        }
        validate_identifiers(event_type, actor)?;
        validate_canonical_payload(payload)?;
        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
            .ok_or_else(|| LedgerError::InvalidTimestamp("clock outside 1970-2554".into()))?;
        // All O(payload) work (hashing, copying) happens before the lock is taken.
        let digest = payload_digest_hex(payload);
        let payload = payload.to_owned();
        let mut store = self.store();
        let sequence = (store.len() as u64) + 1;
        let prev_hash = if let Some(last) = store.last() {
            last.event_hash.clone()
        } else {
            GENESIS_PREV_HASH.to_string()
        };

        // Strictly increasing within the ledger, even if the host clock steps backwards.
        let timestamp = store
            .last()
            .and_then(|last| last.timestamp.parse::<u64>().ok())
            .map_or(now_ns, |last_ns| now_ns.max(last_ns.saturating_add(1)))
            .to_string();
        let event_id = format!("ev_{}_{}", self.ledger_id, sequence);

        let event_hash = hex_string(event_hash_hex(
            sequence, &event_id, &timestamp, event_type, actor, &prev_hash, &digest,
        ));
        let signature = self
            .signing_key
            .as_deref()
            .map(|key| sign_event_hash(key, &event_hash));

        let event = Arc::new(AuditEvent {
            sequence,
            event_id,
            timestamp,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            payload,
            prev_hash,
            event_hash,
            signature,
        });
        store.push(Arc::clone(&event));
        drop(store); // the caller's copy is made outside the critical section
        Ok(Arc::unwrap_or_clone(event))
    }
}

impl AuditLedgerReader for InMemoryLedger {
    fn get_event(&self, sequence: u64) -> Result<Option<AuditEvent>, LedgerError> {
        let store = self.store();
        let event = if sequence == 0 || sequence > (store.len() as u64) {
            None
        } else {
            Some(Arc::clone(&store[(sequence - 1) as usize]))
        };
        drop(store);
        Ok(event.map(Arc::unwrap_or_clone))
    }

    fn head(&self) -> Result<Option<AuditEvent>, LedgerError> {
        let store = self.store();
        let head = store.last().cloned();
        drop(store);
        Ok(head.map(Arc::unwrap_or_clone))
    }

    fn all_events(&self) -> Result<Vec<AuditEvent>, LedgerError> {
        let snapshot = self.snapshot()?;
        Ok(snapshot.into_iter().map(Arc::unwrap_or_clone).collect())
    }
}

impl AuditVerifier for InMemoryLedger {
    fn verify_chain_with(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<ChainVerificationReport, LedgerError> {
        policy.verify(&self.snapshot()?)
    }
}

impl VerificationPolicy {
    /// Verify an exported or persisted event sequence, such as the output of `all_events()`.
    /// Without `self.anchor` this proves internal consistency only.
    pub fn verify<E: Borrow<AuditEvent>>(
        &self,
        events: &[E],
    ) -> Result<ChainVerificationReport, LedgerError> {
        let events: Vec<&AuditEvent> = events.iter().map(Borrow::<AuditEvent>::borrow).collect();
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let checked_at = format!("{}", now_sec);

        if events.is_empty() && self.anchor.is_none() {
            return Ok(ChainVerificationReport {
                valid: true,
                total_events: 0,
                root_hash: String::new(),
                head_hash: String::new(),
                first_broken_sequence: None,
                error_detail: None,
                failure: None,
                checked_at,
            });
        }

        let root_hash = events
            .first()
            .map(|e| e.event_hash.clone())
            .unwrap_or_default();
        let head_hash = events
            .last()
            .map(|e| e.event_hash.clone())
            .unwrap_or_default();
        // `position` is computed by the verifier, never read from the record under test.
        let fail = |position: u64, error: LedgerError| ChainVerificationReport {
            valid: false,
            total_events: events.len(),
            root_hash: root_hash.clone(),
            head_hash: head_hash.clone(),
            first_broken_sequence: Some(position),
            error_detail: Some(error.to_string()),
            failure: Some(error),
            checked_at: checked_at.clone(),
        };
        let mut expected_prev: &str = GENESIS_PREV_HASH;
        let mut prev_timestamp: Option<u64> = None;
        for (idx, event) in events.iter().enumerate() {
            let seq = (idx as u64) + 1;
            if event.sequence != seq {
                let detail = format!("position {seq} records sequence {}", event.sequence);
                return Ok(fail(seq, LedgerError::SequenceDiscontinuity(detail)));
            }
            if event.prev_hash != expected_prev {
                let detail = format!("broken prev_hash link at sequence {seq}");
                return Ok(fail(seq, LedgerError::HashMismatch(detail)));
            }
            let expected_hash = event_hash_hex(
                event.sequence,
                &event.event_id,
                &event.timestamp,
                &event.event_type,
                &event.actor,
                &event.prev_hash,
                &payload_digest_hex(&event.payload),
            );
            if event.event_hash.as_bytes() != expected_hash.as_slice() {
                let detail = format!("tampered content hash at sequence {seq}");
                return Ok(fail(seq, LedgerError::HashMismatch(detail)));
            }
            let Some(timestamp) = parse_canonical_u64(&event.timestamp)
                .filter(|&ns| prev_timestamp.is_none_or(|prev| ns > prev))
            else {
                let detail = format!("timestamp at sequence {seq} is malformed or not increasing");
                return Ok(fail(seq, LedgerError::InvalidTimestamp(detail)));
            };
            prev_timestamp = Some(timestamp);
            if let Some(key) = &self.verifying_key {
                let signed = event.signature.as_deref().is_some_and(|signature| {
                    verify_event_hash_ed25519(&event.event_hash, signature, key.as_bytes())
                });
                if !signed {
                    let detail = format!("missing or invalid signature at sequence {seq}");
                    return Ok(fail(seq, LedgerError::InvalidSignature(detail)));
                }
            }
            expected_prev = &event.event_hash;
        }

        if let Some(anchor) = &self.anchor {
            let witnessed = usize::try_from(anchor.sequence)
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| events.get(i));
            if witnessed.map(|e| &e.event_hash) != Some(&anchor.event_hash) {
                let detail = format!("chain does not contain anchored event {}", anchor.sequence);
                return Ok(fail(anchor.sequence, LedgerError::HashMismatch(detail)));
            }
        }

        Ok(ChainVerificationReport {
            valid: true,
            total_events: events.len(),
            root_hash,
            head_hash,
            first_broken_sequence: None,
            error_detail: None,
            failure: None,
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
    fn test_empty_ledger_verification() {
        let ledger = InMemoryLedger::new();
        let report = ledger
            .verify_chain()
            .expect("Empty chain should verify without panicking");
        assert!(report.valid);
        assert_eq!(report.total_events, 0);
        assert_eq!(report.root_hash, "");
        assert_eq!(report.head_hash, "");
    }

    #[test]
    fn test_append_and_verify_chain() {
        let ledger = InMemoryLedger::new();
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

    #[test]
    fn test_ed25519_signing_and_verification() {
        let priv_bytes = [42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let event_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let sig = sign_event_hash_ed25519(event_hash, &priv_bytes);
        assert!(sig.starts_with("ed25519:"));

        assert!(verify_event_hash_ed25519(event_hash, &sig, &pub_bytes));
        assert!(!verify_event_hash_ed25519(
            "tampered_hash",
            &sig,
            &pub_bytes
        ));
    }
}

#[cfg(test)]
mod remediation_tests;
