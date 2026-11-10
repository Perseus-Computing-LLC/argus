//! # argus-ledger
//!
//! Tamper-evident, append-only SHA-256 audit log for AI agents.
//!
//! When an agent runs commands, calls APIs or changes its memory, a review afterward needs
//! to know what happened and in what order. Ordinary application logs can be edited,
//! reordered or truncated without a trace.
//!
//! Argus keeps an append-only hash chain in which each event records:
//!
//! 1. Its position in the chain (a sequence number).
//! 2. A SHA-256 digest that binds its payload to the previous event's hash (`prev_hash`).
//!
//! Verification walks the chain once and reports the first broken position. Without an
//! anchor it proves internal consistency only: a truncated chain, or one recomputed by
//! someone who can write the log, still passes. Keep a `ChainAnchor` where the writer
//! cannot change it to detect rollback, truncation below the anchor and rewritten history.
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

pub mod file_ledger;
pub use file_ledger::{FileLedger, RecordLines};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The fixed 64-character hexadecimal previous hash for genesis events.
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One event record in the audit chain.
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
    /// Hash format of this record: 2 (current, length-prefixed and domain-tagged) or 1 (legacy
    /// `:`-joined preimage, verify-only). Records written before the field existed parse as 1.
    pub hash_version: u8,
}

/// Hash format written by this version of the crate.
pub const HASH_VERSION: u8 = 2;

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
    /// Events verified under hash format 1, whose field boundaries are not bound into the hash.
    pub legacy_events: usize,
    /// Records below `VerificationPolicy::legacy_timestamps_before` whose timestamp was not
    /// strictly after their predecessor's. Zero unless that option is set.
    pub legacy_timestamp_regressions: usize,
    /// Non-fatal findings. At most one entry today: the count of accepted timestamp
    /// regressions and the first sequence at which one occurred.
    pub warnings: Vec<String>,
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
    /// If set, every anchor checkpoint in this list must be witnessed by the chain.
    pub anchors: Vec<ChainAnchor>,
    /// If set, every event must carry a valid signature by this key; missing, stripped, or
    /// foreign signatures fail verification.
    pub verifying_key: Option<ed25519_dalek::VerifyingKey>,
    /// Accept-as-historic cutoff (issue #14). Ledgers written before the strictly-increasing
    /// timestamp rule can hold records whose timestamp is not after their predecessor's (a
    /// host clock stepping backwards). With this set, such a regression at a sequence below the
    /// cutoff is counted in `ChainVerificationReport::legacy_timestamp_regressions` and reported
    /// as a warning instead of failing the chain. Hashes, `prev_hash` links, sequence continuity,
    /// malformed timestamps and malformed lines stay strict everywhere, and the strict timestamp
    /// rule applies from the cutoff onwards. Must be `>= 1`; `None` leaves behaviour unchanged.
    pub legacy_timestamps_before: Option<u64>,
}

impl AuditEvent {
    /// Commitment to this event's chain position, for publication to an external witness.
    pub fn anchor(&self) -> ChainAnchor {
        ChainAnchor {
            sequence: self.sequence,
            event_hash: self.event_hash.clone(),
        }
    }

    /// Serialize event to a single-line JSON record.
    ///
    /// Every string field goes through serde_json so `"`, `\` and control characters are
    /// escaped: a raw `format!` once let an actor such as `a"b` write a line no reader could
    /// parse. `payload` is spliced in verbatim as a `RawValue` because it is already canonical
    /// JSON (checked by `append`); re-encoding it could change the bytes the hash commits to.
    /// Field order is fixed and matches the Python writer, so the line is byte-identical to
    /// what earlier releases wrote for the same event.
    ///
    /// # Panics
    ///
    /// If `payload` is not valid JSON. Events produced by a ledger always satisfy this; only a
    /// hand-built `AuditEvent` can violate it.
    pub fn to_json_line(&self) -> String {
        #[derive(serde::Serialize)]
        struct Wire<'a> {
            sequence: u64,
            event_id: &'a str,
            timestamp: &'a str,
            event_type: &'a str,
            actor: &'a str,
            payload: &'a serde_json::value::RawValue,
            prev_hash: &'a str,
            event_hash: &'a str,
            signature: Option<&'a str>,
            hash_version: u8,
        }
        let payload: &serde_json::value::RawValue = serde_json::from_str(&self.payload)
            .expect("AuditEvent.payload must be valid JSON (append guarantees it)");
        serde_json::to_string(&Wire {
            sequence: self.sequence,
            event_id: &self.event_id,
            timestamp: &self.timestamp,
            event_type: &self.event_type,
            actor: &self.actor,
            payload,
            prev_hash: &self.prev_hash,
            event_hash: &self.event_hash,
            signature: self.signature.as_deref(),
            hash_version: self.hash_version,
        })
        .expect("Wire holds only integers and strings; serialization cannot fail")
    }

    /// Parse one stored record. The line must hold exactly the members a writer emits, once
    /// each: an unknown member or a repeated one is added text that no hash or signature covers,
    /// so it is refused here rather than ignored. `hash_version`, when present, must be the
    /// integer 1 or 2. The payload is read by [`canonical_stored_payload`].
    pub fn from_json_line(line: &str) -> Result<Self, LedgerError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRef<'a> {
            sequence: u64,
            #[serde(borrow)]
            event_id: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            timestamp: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            event_type: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            actor: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            payload: &'a serde_json::value::RawValue,
            #[serde(borrow)]
            prev_hash: std::borrow::Cow<'a, str>,
            #[serde(borrow)]
            event_hash: std::borrow::Cow<'a, str>,
            #[serde(default, borrow)]
            signature: Option<std::borrow::Cow<'a, str>>,
            #[serde(default, deserialize_with = "present")]
            hash_version: Option<serde_json::Value>,
        }

        /// Keeps an explicit `"hash_version":null` apart from an absent member: only the
        /// latter is a record written before the field existed.
        fn present<'de, D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<serde_json::Value>, D::Error> {
            serde::Deserialize::deserialize(deserializer).map(Some)
        }

        // One record is one line: padding at the ends is dropped, a line break inside the
        // record is not JSON a writer produces and the Python reader would split or refuse it.
        // The derive below would also read a JSON array as the fields in order; only the
        // object form is a record.
        let line = line.trim_matches(RECORD_PADDING);
        if line.contains(['\r', '\n']) {
            let detail = "malformed JSON: line break inside a record";
            return Err(LedgerError::InvalidInput(detail.to_string()));
        }
        if !line.starts_with('{') {
            let detail = "malformed JSON: a record must be a JSON object";
            return Err(LedgerError::InvalidInput(detail.to_string()));
        }
        let wire: WireRef = serde_json::from_str(line)
            .map_err(|e| LedgerError::InvalidInput(format!("malformed JSON: {e}")))?;

        let hash_version = match &wire.hash_version {
            None => 1,
            Some(v) => match v.as_u64() {
                Some(1) => 1,
                Some(2) => 2,
                _ => {
                    let detail = format!("unsupported hash_version {v}");
                    return Err(LedgerError::InvalidInput(detail));
                }
            },
        };
        let payload = canonical_stored_payload(wire.payload.get())?;

        Ok(Self {
            sequence: wire.sequence,
            event_id: wire.event_id.to_string(),
            timestamp: wire.timestamp.to_string(),
            event_type: wire.event_type.to_string(),
            actor: wire.actor.to_string(),
            payload,
            prev_hash: wire.prev_hash.to_string(),
            event_hash: wire.event_hash.to_string(),
            signature: wire.signature.map(|s| s.to_string()),
            hash_version,
        })
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
/// The signed message is the current one (format 2: domain tag, then the hash).
pub fn verify_event_hash_ed25519(
    event_hash: &str,
    signature_hex: &str,
    public_key_bytes: &[u8; 32],
) -> bool {
    verify_event_signature_ed25519(event_hash, signature_hex, public_key_bytes, HASH_VERSION)
}

/// Verify the signature of a record written in hash format `hash_version`. A format-1 signature
/// covers the bare event hash; format 2 covers the domain tag followed by the hash. This is the
/// rule `argus_ledger.hasher` applies, so a signed format-1 ledger gets the same verdict from
/// both verifiers.
pub fn verify_event_signature_ed25519(
    event_hash: &str,
    signature_hex: &str,
    public_key_bytes: &[u8; 32],
    hash_version: u8,
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
    let message = match hash_version {
        1 => event_hash.as_bytes().to_vec(),
        _ => [SIGNATURE_DOMAIN, event_hash.as_bytes()].concat(),
    };
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
/// `"` (0x22) and `\` (0x5C) are ASCII-graphic but are JSON string syntax; they are excluded so
/// an actor can never carry JSON structure even if a future serializer forgets to escape it.
/// The Python writer (`argus_ledger.canonical.validate_identifiers`) applies the same grammar.
fn validate_identifiers(event_type: &str, actor: &str) -> Result<(), LedgerError> {
    let type_byte = |b: u8| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-');
    let segment = |s: &str| !s.is_empty() && s.bytes().all(type_byte);
    if event_type.len() > MAX_IDENTIFIER_BYTES || !event_type.split('.').all(segment) {
        let detail = "event_type must be dot-separated [a-z0-9_-]+ segments";
        return Err(LedgerError::InvalidInput(detail.into()));
    }
    let actor_byte = |b: u8| b.is_ascii_graphic() && b != b'"' && b != b'\\';
    if actor.is_empty() || actor.len() > MAX_IDENTIFIER_BYTES || !actor.bytes().all(actor_byte) {
        let detail = "actor must be printable ASCII without whitespace, quotes or backslashes";
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
    // Bounded by serde_json's own parse limit, so the recursion here is too.
    fn depth(value: &serde_json::Value) -> usize {
        match value {
            serde_json::Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
            serde_json::Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
            _ => 0,
        }
    }
    let invalid = |reason: &str| LedgerError::InvalidInput(format!("payload {reason}"));
    let value: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| invalid("is not valid JSON"))?;
    if !value.is_object() || !canonical(&value) {
        return Err(invalid("must be a sorted-key object with safe integers"));
    }
    if depth(&value) > MAX_PAYLOAD_DEPTH {
        return Err(invalid("is nested deeper than MAX_PAYLOAD_DEPTH levels"));
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

/// Deepest nesting `append` accepts, counting the payload object itself as level 1. The Python
/// writer applies the same number (`argus_ledger.canonical.MAX_PAYLOAD_DEPTH`). It sits below
/// [`MAX_STORED_PAYLOAD_DEPTH`] so that no writer produces a record a verifier cannot read.
pub const MAX_PAYLOAD_DEPTH: usize = 112;
/// Deepest nesting either verifier reads in a stored payload; a deeper one is a malformed
/// record. 127 is where `serde_json` stopped reading, so ledgers that verified before still do.
pub const MAX_STORED_PAYLOAD_DEPTH: usize = 127;
/// Characters every reader drops from both ends of a line before parsing it. A line that is
/// empty afterwards is blank and skipped; any other line is a record. `argus_ledger.ledger`
/// applies the same rule, so no reader calls a line blank that another one parses.
pub const RECORD_PADDING: [char; 4] = [' ', '\t', '\r', '\n'];
/// Longest integer token either verifier reads in a stored payload (the Python verifier's
/// integer parser stops at this many digits).
const MAX_INTEGER_DIGITS: usize = 4300;

/// Canonical text of a stored payload: compact, keys sorted by code point, strings escaped the
/// way `serde_json` and Python's `json.dumps(ensure_ascii=False)` escape them, integers as
/// stored and floats as Python's `repr` prints them (the text the Python writer hashed before
/// floats were refused).
///
/// The payload is read token by token so that the Python verifier can apply the same rules to
/// the same bytes. Refused as malformed: a payload that is not an object, an object with a
/// repeated key at any depth, the integer token `-0`, an integer longer than
/// [`MAX_INTEGER_DIGITS`], a float that overflows a double, and nesting beyond
/// [`MAX_STORED_PAYLOAD_DEPTH`].
pub fn canonical_stored_payload(raw: &str) -> Result<String, LedgerError> {
    let mut scanner = PayloadScanner {
        text: raw,
        bytes: raw.as_bytes(),
        pos: 0,
    };
    scanner.skip_whitespace();
    if scanner.peek() != Some(b'{') {
        return Err(scanner.malformed("payload must be a JSON object"));
    }
    let mut out = String::with_capacity(raw.len());
    scanner.value(&mut out, 1)?;
    scanner.skip_whitespace();
    if scanner.pos != scanner.bytes.len() {
        return Err(scanner.malformed("unexpected text after the payload"));
    }
    Ok(out)
}

struct PayloadScanner<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> PayloadScanner<'a> {
    fn malformed(&self, reason: &str) -> LedgerError {
        LedgerError::InvalidInput(format!("malformed payload at byte {}: {reason}", self.pos))
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), LedgerError> {
        if self.peek() != Some(byte) {
            return Err(self.malformed(&format!("expected `{}`", byte as char)));
        }
        self.pos += 1;
        Ok(())
    }

    /// Append the canonical text of the value at `pos` to `out`. `depth` is the level the
    /// value would occupy if it is an object or array.
    fn value(&mut self, out: &mut String, depth: usize) -> Result<(), LedgerError> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(out, depth),
            Some(b'[') => self.array(out, depth),
            Some(b'"') => {
                let (_, canonical) = self.string()?;
                out.push_str(&canonical);
                Ok(())
            }
            Some(b'-' | b'0'..=b'9') => self.number(out),
            _ => {
                for literal in ["true", "false", "null"] {
                    if self.text[self.pos..].starts_with(literal) {
                        self.pos += literal.len();
                        out.push_str(literal);
                        return Ok(());
                    }
                }
                Err(self.malformed("expected a JSON value"))
            }
        }
    }

    fn enter(&mut self, depth: usize) -> Result<(), LedgerError> {
        if depth > MAX_STORED_PAYLOAD_DEPTH {
            return Err(self.malformed("nested deeper than MAX_STORED_PAYLOAD_DEPTH levels"));
        }
        self.pos += 1;
        self.skip_whitespace();
        Ok(())
    }

    fn array(&mut self, out: &mut String, depth: usize) -> Result<(), LedgerError> {
        self.enter(depth)?;
        out.push('[');
        if self.peek() == Some(b']') {
            self.pos += 1;
            out.push(']');
            return Ok(());
        }
        loop {
            self.value(out, depth + 1)?;
            self.skip_whitespace();
            if self.peek() == Some(b',') {
                self.pos += 1;
                out.push(',');
            } else {
                self.expect(b']')?;
                out.push(']');
                return Ok(());
            }
        }
    }

    fn object(&mut self, out: &mut String, depth: usize) -> Result<(), LedgerError> {
        self.enter(depth)?;
        if self.peek() == Some(b'}') {
            self.pos += 1;
            out.push_str("{}");
            return Ok(());
        }
        // Each member's canonical text, keyed by the decoded key. Members are written in key
        // order afterwards, whatever order they were stored in.
        let mut members: Vec<(std::borrow::Cow<'a, str>, String)> = Vec::new();
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.malformed("expected an object key"));
            }
            let (key, canonical_key) = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let mut member = canonical_key.into_owned();
            member.push(':');
            self.value(&mut member, depth + 1)?;
            members.push((key, member));
            self.skip_whitespace();
            if self.peek() == Some(b',') {
                self.pos += 1;
            } else {
                self.expect(b'}')?;
                break;
            }
        }
        members.sort_by(|a, b| a.0.cmp(&b.0));
        if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(self.malformed("an object repeats a key"));
        }
        out.push('{');
        for (index, (_, member)) in members.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(member);
        }
        out.push('}');
        Ok(())
    }

    /// The string token at `pos`: its decoded value and its canonical JSON text.
    #[allow(clippy::type_complexity)]
    fn string(
        &mut self,
    ) -> Result<(std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>), LedgerError> {
        let start = self.pos;
        let mut escaped = false;
        self.pos += 1;
        loop {
            match self.peek() {
                None => return Err(self.malformed("unterminated string")),
                Some(b'"') => break,
                Some(b'\\') => {
                    escaped = true;
                    self.pos += 2;
                }
                Some(byte) if byte < 0x20 => {
                    return Err(self.malformed("control character in a string"));
                }
                Some(_) => self.pos += 1,
            }
        }
        self.pos += 1;
        let text: &'a str = self.text;
        let token = &text[start..self.pos];
        if !escaped {
            // No escapes and no control characters: the token is already its canonical text.
            return Ok((token[1..token.len() - 1].into(), token.into()));
        }
        let decoded: String = serde_json::from_str(token)
            .map_err(|e| self.malformed(&format!("invalid string: {e}")))?;
        let canonical = serde_json::to_string(&decoded)
            .map_err(|e| self.malformed(&format!("cannot serialize string: {e}")))?;
        Ok((decoded.into(), canonical.into()))
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        self.pos - start
    }

    fn number(&mut self, out: &mut String) -> Result<(), LedgerError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let integer_digits = match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                1
            }
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(self.malformed("invalid number")),
        };
        let mut float = false;
        if self.peek() == Some(b'.') {
            self.pos += 1;
            float = true;
            if self.digits() == 0 {
                return Err(self.malformed("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            float = true;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err(self.malformed("invalid number"));
            }
        }
        if matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.malformed("invalid number"));
        }
        let token = &self.text[start..self.pos];
        if !float {
            // Python reads `-0` as the integer 0; hashing either spelling would let the two
            // verifiers disagree, and no writer emits it.
            if token == "-0" {
                return Err(self.malformed("integer token `-0`"));
            }
            if integer_digits > MAX_INTEGER_DIGITS {
                return Err(self.malformed("integer has more than MAX_INTEGER_DIGITS digits"));
            }
            out.push_str(token);
            return Ok(());
        }
        match token.parse::<f64>() {
            Ok(value) if value.is_finite() => {
                out.push_str(&python_float_repr(value));
                Ok(())
            }
            _ => Err(self.malformed("float outside the range of a double")),
        }
    }
}

/// `repr(float)` as Python prints it, which is what `json.dumps` writes and therefore what the
/// Python writer hashed while it still accepted floats: the shortest digits that read back to
/// the same double, exponent form below 1e-4 and from 1e16 (`1e-07`, `1.5e-05`, `1e+16`),
/// otherwise positional with at least one fractional digit (`0.5`, `100.0`).
fn python_float_repr(value: f64) -> String {
    // `{:e}` gives the same shortest digits as `d[.ddd]e[-]x`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` output of a finite float has an exponent");
    let exponent: i32 = exponent
        .parse()
        .expect("`{:e}` exponent of a finite float is an integer");
    let (sign, mantissa) = match mantissa.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", mantissa),
    };
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let mut out = String::from(sign);
    if !(-4..16).contains(&exponent) {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exponent.unsigned_abs()));
    } else if exponent < 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-exponent - 1) as usize));
        out.push_str(&digits);
    } else {
        let integer_len = exponent as usize + 1;
        if digits.len() <= integer_len {
            out.push_str(&digits);
            out.push_str(&"0".repeat(integer_len - digits.len()));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..integer_len]);
            out.push('.');
            out.push_str(&digits[integer_len..]);
        }
    }
    out
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

/// Parse a record timestamp to nanoseconds since the UNIX epoch: either a decimal `u64` in
/// canonical form (no sign, no leading zeros; what the Rust writers emit) or an RFC 3339 date-time
/// with any UTC offset (what the Python writer emits). Both forms compare as instants, so the
/// timestamp contract, strictly increasing within a ledger, holds across writers.
pub fn parse_timestamp_nanos(s: &str) -> Option<u64> {
    let canonical = s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if canonical {
        if let Ok(v) = s.parse() {
            return Some(v);
        }
    }
    parse_iso8601_nanos(s)
}

/// Split a trailing `Z`, `+hh:mm` or `-hh:mm` off an ISO-8601 string and return the offset in
/// seconds east of UTC. No suffix is treated as UTC. Returns None for a malformed offset.
/// Before this existed `+05:00` records failed to parse and `Z` records were read as UTC only by
/// luck of the fraction parser, so Python-written ledgers could not be verified by this crate.
/// A decimal field of a timestamp: ASCII digits only. `str::parse` on its own also accepts a
/// leading `+` (and `-` for signed types), which the Python parser does not.
fn decimal_field<T: std::str::FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn split_utc_offset(s: &str) -> Option<(&str, i64)> {
    if let Some(body) = s.strip_suffix('Z') {
        return Some((body, 0));
    }
    let Some(cut) = s.len().checked_sub(6) else {
        return Some((s, 0));
    };
    let (body, off) = s.split_at(cut);
    let sign = match off.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return Some((s, 0)), // no offset present (e.g. ends in fraction digits)
    };
    if off.as_bytes()[3] != b':' {
        return None;
    }
    let hh: i64 = decimal_field(&off[1..3])?;
    let mm: i64 = decimal_field(&off[4..6])?;
    (hh <= 14 && mm <= 59).then_some((body, sign * (hh * 3600 + mm * 60)))
}

fn parse_iso8601_nanos(s: &str) -> Option<u64> {
    // The grammar is ASCII; refusing anything else here also keeps the byte offsets below on
    // character boundaries.
    if !s.is_ascii() {
        return None;
    }
    let (s, offset_secs) = split_utc_offset(s)?;
    let bytes = s.as_bytes();
    if bytes.len() < 19
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let y: i64 = decimal_field(s.get(0..4)?)?;
    let m: u64 = decimal_field(s.get(5..7)?)?;
    let d: u64 = decimal_field(s.get(8..10)?)?;
    let hour: u64 = decimal_field(s.get(11..13)?)?;
    let min: u64 = decimal_field(s.get(14..16)?)?;
    let sec: u64 = decimal_field(s.get(17..19)?)?;

    // Year 0000 is outside the grammar on both sides (Python's calendar has no year 0).
    if y == 0 {
        return None;
    }
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }

    // Days from civil (Howard Hinnant's algorithm), valid for the proleptic Gregorian calendar.
    let y_adj = y - if m <= 2 { 1 } else { 0 };
    let era = (if y_adj >= 0 { y_adj } else { y_adj - 399 }) / 400;
    let yoe = (y_adj - era * 400) as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe as i64 - 719468;
    let local_secs = days * 86400 + (hour * 3600 + min * 60 + sec) as i64;
    let epoch_secs = u64::try_from(local_secs - offset_secs).ok()?;

    let mut nanos = 0u64;
    if let Some(frac) = s[19..].strip_prefix('.') {
        // Only digits may follow the dot now that the offset has been split off.
        if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let digits = frac.len().min(9);
        let mut frac_val: u64 = frac[..digits].parse().ok()?;
        for _ in digits..9 {
            frac_val *= 10;
        }
        nanos = frac_val;
    } else if s.len() != 19 {
        return None;
    }

    epoch_secs.checked_mul(1_000_000_000)?.checked_add(nanos)
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
        getrandom::fill(&mut id).expect("OS RNG unavailable; cannot derive a ledger identity");
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
        // The last record may be in either form (a Python writer may have appended before us).
        let timestamp = store
            .last()
            .and_then(|last| parse_timestamp_nanos(&last.timestamp))
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
            hash_version: HASH_VERSION,
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
    /// Verify an exported or in-memory event sequence, such as the output of `all_events()`.
    /// Without `self.anchor` this proves internal consistency only.
    pub fn verify<E: Borrow<AuditEvent>>(
        &self,
        events: &[E],
    ) -> Result<ChainVerificationReport, LedgerError> {
        self.verify_stream(events.iter().map(|e| Ok(e.borrow().clone())))
    }

    /// Verify records as they are produced, holding one record at a time, so a file of any
    /// length costs constant memory. An `Err` item is a record that could not be parsed: it
    /// fails the chain at the position it would have occupied (fail closed), which is how the
    /// Python package and the `argus-verify` CLI treat a torn or vandalised line.
    ///
    /// On failure `total_events` is the number of records examined up to and including the
    /// broken one and `head_hash` is the last record that verified; the rest of the input is
    /// not consumed.
    pub fn verify_stream<I>(&self, records: I) -> Result<ChainVerificationReport, LedgerError>
    where
        I: IntoIterator<Item = Result<AuditEvent, LedgerError>>,
    {
        // Sequence numbers start at 1, so a cutoff of 0 can only be a caller mistake; refuse it
        // rather than silently behaving as if the option were unset.
        if self.legacy_timestamps_before == Some(0) {
            return Err(LedgerError::InvalidInput(
                "legacy_timestamps_before must be >= 1".into(),
            ));
        }
        let mut verifier = ChainVerifier::new(self);
        for record in records {
            match record {
                Ok(event) => {
                    if let Some(report) = verifier.push(&event) {
                        return Ok(report);
                    }
                }
                Err(error) => return Ok(verifier.fail_next(error)),
            }
        }
        Ok(verifier.finish())
    }
}

/// Incremental chain verifier behind [`VerificationPolicy::verify_stream`]: feed records in file
/// order with [`ChainVerifier::push`], then call [`ChainVerifier::finish`]. Only the running
/// state (expected link, last instant, counters) is kept between records.
pub struct ChainVerifier<'a> {
    policy: &'a VerificationPolicy,
    position: u64,
    expected_prev: String,
    prev_timestamp: Option<u64>,
    legacy_events: usize,
    legacy_timestamp_regressions: usize,
    first_legacy_regression: Option<u64>,
    root_hash: String,
    head_hash: String,
    anchor_matched: bool,
    anchors_matched: std::collections::HashSet<u64>,
    checked_at: String,
}

impl<'a> ChainVerifier<'a> {
    pub fn new(policy: &'a VerificationPolicy) -> Self {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            policy,
            position: 0,
            expected_prev: GENESIS_PREV_HASH.to_string(),
            prev_timestamp: None,
            legacy_events: 0,
            legacy_timestamp_regressions: 0,
            first_legacy_regression: None,
            root_hash: String::new(),
            head_hash: String::new(),
            anchor_matched: false,
            anchors_matched: std::collections::HashSet::new(),
            checked_at: format!("{now_sec}"),
        }
    }

    /// Records examined so far.
    pub fn position(&self) -> u64 {
        self.position
    }

    /// The single warning for accepted timestamp regressions, if any were counted. One line
    /// rather than one per record: a historic ledger can hold dozens and the count plus the
    /// first position is what an operator needs to decide whether the cutoff is right.
    fn warnings(&self) -> Vec<String> {
        match self.first_legacy_regression {
            Some(first) => vec![format!(
                "{} timestamp regression(s) accepted as historic below sequence {} (first at sequence {first})",
                self.legacy_timestamp_regressions,
                self.policy.legacy_timestamps_before.unwrap_or(0),
            )],
            None => Vec::new(),
        }
    }

    /// `position` is computed by the verifier, never read from the record under test.
    fn report(&self, position: u64, error: LedgerError) -> ChainVerificationReport {
        ChainVerificationReport {
            valid: false,
            total_events: self.position as usize,
            root_hash: self.root_hash.clone(),
            head_hash: self.head_hash.clone(),
            first_broken_sequence: Some(position),
            error_detail: Some(error.to_string()),
            failure: Some(error),
            checked_at: self.checked_at.clone(),
            legacy_events: self.legacy_events,
            legacy_timestamp_regressions: self.legacy_timestamp_regressions,
            warnings: self.warnings(),
        }
    }

    /// Fail the chain at the position the next record would have occupied: for a line that
    /// could not be parsed into a record at all.
    pub fn fail_next(&mut self, error: LedgerError) -> ChainVerificationReport {
        self.position += 1;
        self.report(self.position, error)
    }

    /// Check one record against the running state. `Some(report)` means the chain is broken
    /// here and no further record should be pushed.
    pub fn push(&mut self, event: &AuditEvent) -> Option<ChainVerificationReport> {
        self.position += 1;
        let seq = self.position;
        if event.sequence != seq {
            let detail = format!("position {seq} records sequence {}", event.sequence);
            return Some(self.report(seq, LedgerError::SequenceDiscontinuity(detail)));
        }
        if event.prev_hash != self.expected_prev {
            let detail = format!("broken prev_hash link at sequence {seq}");
            return Some(self.report(seq, LedgerError::HashMismatch(detail)));
        }
        // The record's own hash_version selects the preimage. Relabelling cannot make a
        // record verify: its stored hash commits to exactly one format.
        if !event_hash_matches(event) {
            let detail = format!("tampered content hash at sequence {seq}");
            return Some(self.report(seq, LedgerError::HashMismatch(detail)));
        }
        // A timestamp that does not parse is always a failure. One that parses but is not
        // strictly after its predecessor is a failure unless the record lies below the
        // accept-as-historic cutoff (issue #14), in which case it is counted and reported once.
        let Some(timestamp) = parse_timestamp_nanos(&event.timestamp) else {
            let detail = format!("timestamp at sequence {seq} is malformed or not increasing");
            return Some(self.report(seq, LedgerError::InvalidTimestamp(detail)));
        };
        if self.prev_timestamp.is_some_and(|prev| timestamp <= prev) {
            let historic = self
                .policy
                .legacy_timestamps_before
                .is_some_and(|cutoff| seq < cutoff);
            if !historic {
                let detail = format!("timestamp at sequence {seq} is malformed or not increasing");
                return Some(self.report(seq, LedgerError::InvalidTimestamp(detail)));
            }
            self.legacy_timestamp_regressions += 1;
            self.first_legacy_regression.get_or_insert(seq);
        }
        if let Some(key) = &self.policy.verifying_key {
            let signed = event.signature.as_deref().is_some_and(|signature| {
                verify_event_signature_ed25519(
                    &event.event_hash,
                    signature,
                    key.as_bytes(),
                    event.hash_version,
                )
            });
            if !signed {
                let detail = format!("missing or invalid signature at sequence {seq}");
                return Some(self.report(seq, LedgerError::InvalidSignature(detail)));
            }
        }
        if let Some(anchor) = &self.policy.anchor {
            if anchor.sequence == seq {
                if anchor.event_hash != event.event_hash {
                    let detail = format!("chain does not contain anchored event {seq}");
                    return Some(self.report(seq, LedgerError::HashMismatch(detail)));
                }
                self.anchor_matched = true;
            }
        }
        for anchor in &self.policy.anchors {
            if anchor.sequence == seq {
                if anchor.event_hash != event.event_hash {
                    let detail = format!("chain does not contain anchored event {seq}");
                    return Some(self.report(seq, LedgerError::HashMismatch(detail)));
                }
                self.anchors_matched.insert(seq);
            }
        }
        self.legacy_events += usize::from(event.hash_version == 1);
        self.prev_timestamp = Some(timestamp);
        if seq == 1 {
            self.root_hash = event.event_hash.clone();
        }
        self.head_hash = event.event_hash.clone();
        self.expected_prev = event.event_hash.clone();
        None
    }

    /// End of input: the anchor, if any, must have been seen, otherwise the file was truncated
    /// or rolled back below it.
    pub fn finish(self) -> ChainVerificationReport {
        if let Some(anchor) = &self.policy.anchor {
            if !self.anchor_matched {
                let detail = format!("chain does not contain anchored event {}", anchor.sequence);
                return self.report(anchor.sequence, LedgerError::HashMismatch(detail));
            }
        }
        for anchor in &self.policy.anchors {
            if !self.anchors_matched.contains(&anchor.sequence) {
                let detail = format!("chain does not contain anchored event {}", anchor.sequence);
                return self.report(anchor.sequence, LedgerError::HashMismatch(detail));
            }
        }
        ChainVerificationReport {
            valid: true,
            total_events: self.position as usize,
            warnings: self.warnings(),
            root_hash: self.root_hash,
            head_hash: self.head_hash,
            first_broken_sequence: None,
            error_detail: None,
            failure: None,
            checked_at: self.checked_at,
            legacy_events: self.legacy_events,
            legacy_timestamp_regressions: self.legacy_timestamp_regressions,
        }
    }
}

/// Recompute `event.event_hash` in the record's own format and compare.
fn event_hash_matches(event: &AuditEvent) -> bool {
    match event.hash_version {
        2 => {
            let expected = event_hash_hex(
                event.sequence,
                &event.event_id,
                &event.timestamp,
                &event.event_type,
                &event.actor,
                &event.prev_hash,
                &payload_digest_hex(&event.payload),
            );
            event.event_hash.as_bytes() == expected.as_slice()
        }
        1 => event.event_hash == legacy_v1_event_hash(event),
        _ => false,
    }
}

/// Hash format 1, verify-only: SHA-256 over `seq:id:ts:type:actor:prev:` followed by the
/// payload text. Fields were not length-prefixed, so text could move between adjacent fields
/// without changing the hash; that is why format 2 replaced it. Kept so ledgers that span the
/// format change still verify in the library as they do in the Python package.
fn legacy_v1_event_hash(event: &AuditEvent) -> String {
    let header = format!(
        "{}:{}:{}:{}:{}:{}:",
        event.sequence,
        event.event_id,
        event.timestamp,
        event.event_type,
        event.actor,
        event.prev_hash
    );
    let mut hasher = Sha256::new_with_prefix(header.as_bytes());
    hasher.update(event.payload.as_bytes());
    hex_string(digest_hex(&hasher.finalize().into()))
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
