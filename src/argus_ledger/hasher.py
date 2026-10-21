"""Cryptographic hashing and signing for audit events.

Hash format 2, written by this version, is byte-identical to the Rust crate: SHA-256 over the domain
tag ``argus.event.v2\\0``, the sequence as a big-endian u64, then event_id, timestamp, event_type,
actor, prev_hash and the payload digest, each prefixed by its big-endian u64 byte length. The payload
digest is SHA-256 over ``argus.payload.v2\\0`` and the canonical JSON payload. Signatures over a
format-2 event cover ``argus.event.sig.v1\\0`` followed by the event hash.

Format 1 is still verified for records written before ``AuditEvent.hash_version`` existed, but never
written: it joined fields with ``:``, so text could move between adjacent fields without changing the
hash (``event_type="a:b", actor="c"`` and ``event_type="a", actor="b:c"`` collide).
"""

from __future__ import annotations

import hashlib
import hmac
import operator
import re
from typing import Any, Dict

from .canonical import canonical_json_bytes
from .models import CURRENT_HASH_VERSION, AuditEvent

_EVENT_HASH_DOMAIN = b"argus.event.v2\x00"
_PAYLOAD_HASH_DOMAIN = b"argus.payload.v2\x00"
SIGNATURE_DOMAIN = b"argus.event.sig.v1\x00"
_ED25519_PREFIX = "ed25519:"
_ED25519_SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}")

# The eight small-order Edwards25519 points with the sign bit cleared, including the non-canonical
# encodings of y = 0 and y = 1 (as rejected by libsodium). Under a small-order public key forged
# signatures verify; for the identity key, R = identity and S = 0 verifies every message, and
# OpenSSL's Ed25519 accepts it.
_SMALL_ORDER_POINTS = frozenset(
    bytes.fromhex(encoded)
    for encoded in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)


def _has_small_order(point: bytes) -> bool:
    return point[:31] + bytes((point[31] & 0x7F,)) in _SMALL_ORDER_POINTS


def compute_payload_digest(payload: Dict[str, Any]) -> str:
    """Format-2 payload digest: SHA-256 over the payload domain tag and the canonical JSON payload."""
    hasher = hashlib.sha256(_PAYLOAD_HASH_DOMAIN)
    hasher.update(canonical_json_bytes(payload))
    return hasher.hexdigest()


def compute_event_hash(
    sequence: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    actor: str,
    prev_hash: str,
    payload: Dict[str, Any],
    *,
    hash_version: int = CURRENT_HASH_VERSION,
) -> str:
    """Compute the SHA-256 event hash in format ``hash_version`` (default: the current format)."""
    if hash_version == 1:
        header = f"{sequence}:{event_id}:{timestamp}:{event_type}:{actor}:{prev_hash}:"
        hasher = hashlib.sha256(header.encode("utf-8"))
        hasher.update(canonical_json_bytes(payload))
        return hasher.hexdigest()
    if hash_version != 2:
        raise ValueError(f"unsupported hash_version: {hash_version!r}")
    fields = (event_id, timestamp, event_type, actor, prev_hash)
    if not all(isinstance(field, str) for field in fields):
        raise TypeError("event_id, timestamp, event_type, actor and prev_hash must be str")
    hasher = hashlib.sha256(_EVENT_HASH_DOMAIN)
    hasher.update(operator.index(sequence).to_bytes(8, "big"))
    for field in (*fields, compute_payload_digest(payload)):
        data = field.encode("utf-8")
        hasher.update(len(data).to_bytes(8, "big"))
        hasher.update(data)
    return hasher.hexdigest()


def verify_event(event: AuditEvent) -> bool:
    """Verify that an event's hash matches its contents, in the event's own hash format."""
    try:
        expected_hash = compute_event_hash(
            sequence=event.sequence,
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            actor=event.actor,
            prev_hash=event.prev_hash,
            payload=event.payload,
            hash_version=event.hash_version,
        )
    except (TypeError, ValueError, OverflowError):
        # Out-of-range numbers, unencodable text or an out-of-range sequence: not a record this
        # ledger can have written.
        return False
    return event.event_hash == expected_hash


def _signed_message(event_hash: str, hash_version: int) -> bytes:
    message = event_hash.encode("ascii")
    return message if hash_version == 1 else SIGNATURE_DOMAIN + message


def sign_event_hash(event_hash: str, key: bytes, *, hash_version: int = CURRENT_HASH_VERSION) -> str:
    """HMAC-SHA256 signature of an event hash, as lowercase hex.

    From format 2 on, the MAC covers the signature domain tag followed by the hash."""
    return hmac.new(key, _signed_message(event_hash, hash_version), hashlib.sha256).hexdigest()


def sign_event_hash_ed25519(
    event_hash: str, private_key_bytes: bytes, *, hash_version: int = CURRENT_HASH_VERSION
) -> str:
    """Ed25519 signature (``ed25519:`` + lowercase hex) of an event hash under a 32-byte private
    seed. Format-2 signatures are byte-identical to the Rust crate's ``sign_event_hash_ed25519``."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return _ED25519_PREFIX + priv.sign(_signed_message(event_hash, hash_version)).hex()


def ed25519_public_key(private_key_bytes: bytes) -> bytes:
    """Raw 32-byte Ed25519 public key for a 32-byte private seed."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def verify_signature_ed25519(event: AuditEvent, public_key_bytes: bytes) -> bool:
    """Verify an event's Ed25519 signature with a 32-byte public key.

    Strict, as ed25519-dalek's ``verify_strict``: only the lowercase-hex ``ed25519:`` encoding is
    accepted, and small-order public keys and ``R`` points are rejected."""
    signature = event.signature
    if not signature or not signature.startswith(_ED25519_PREFIX):
        return False
    encoded = signature[len(_ED25519_PREFIX):]
    if not _ED25519_SIGNATURE_HEX.fullmatch(encoded):
        return False
    sig_bytes = bytes.fromhex(encoded)
    public_key_bytes = bytes(public_key_bytes)
    if len(public_key_bytes) != 32 or _has_small_order(public_key_bytes) or _has_small_order(sig_bytes[:32]):
        return False
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    try:
        message = _signed_message(event.event_hash, event.hash_version)
        ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(sig_bytes, message)
    except (ValueError, InvalidSignature):
        return False
    return True


SIGNATURE_SCHEMES = ("hmac", "ed25519")


def verify_signature(event: AuditEvent, key: bytes, *, scheme: str = "hmac") -> bool:
    """True when the event carries a valid ``scheme`` signature under ``key``.

    The verifier chooses the scheme; the signature never does. ``"hmac"`` checks an HMAC-SHA256
    signature under the secret ``key``. ``"ed25519"`` checks an ``ed25519:`` signature under the
    32-byte public ``key``. A signature in the other scheme fails. Letting the signature choose let
    anyone who knew an Ed25519 public key forge events: as an HMAC keyed with the public key, or as
    an Ed25519 signature made with the public key's bytes as a private seed.
    """
    if scheme == "ed25519":
        return verify_signature_ed25519(event, key)
    if scheme != "hmac":
        raise ValueError(f"unknown signature scheme {scheme!r}; expected one of {SIGNATURE_SCHEMES}")
    signature = event.signature
    if not signature or signature.startswith(_ED25519_PREFIX):
        return False
    try:
        expected = sign_event_hash(event.event_hash, key, hash_version=event.hash_version)
    except ValueError:  # a non-ASCII event hash was not produced by this ledger
        return False
    return hmac.compare_digest(signature.encode("utf-8"), expected.encode("ascii"))
