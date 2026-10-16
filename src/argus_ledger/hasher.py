"""Cryptographic hashing and verification functions for audit events."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict
from .canonical import canonical_json_bytes
from .models import AuditEvent


def compute_event_hash(
    sequence: int,
    event_id: str,
    timestamp: str,
    event_type: str,
    actor: str,
    prev_hash: str,
    payload: Dict[str, Any],
) -> str:
    """Compute the deterministic SHA-256 hash for an audit event."""
    header = f"{sequence}:{event_id}:{timestamp}:{event_type}:{actor}:{prev_hash}:"
    header_bytes = header.encode("utf-8")
    payload_bytes = canonical_json_bytes(payload)

    hasher = hashlib.sha256()
    hasher.update(header_bytes)
    hasher.update(payload_bytes)
    return hasher.hexdigest()


def verify_event(event: AuditEvent) -> bool:
    """Verify that an event's hash matches its contents."""
    expected_hash = compute_event_hash(
        sequence=event.sequence,
        event_id=event.event_id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        actor=event.actor,
        prev_hash=event.prev_hash,
        payload=event.payload,
    )
    return event.event_hash == expected_hash


def sign_event_hash(event_hash: str, key: bytes) -> str:
    """Sign an event hash.
    If key is 32 or 64 bytes and looks like an Ed25519 private key, or if HMAC-SHA256 is used:
    Supports Ed25519 asymmetric signatures (prefixed with 'ed25519:') when key is 32 bytes and Ed25519 format is chosen,
    or standard HMAC-SHA256 hex signatures.
    """
    return hmac.new(key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()


def sign_event_hash_ed25519(event_hash: str, private_key_bytes: bytes) -> str:
    """Sign an event hash using Ed25519 asymmetric private key (32 bytes raw seed/key)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = priv.sign(event_hash.encode("ascii"))
    return "ed25519:" + sig.hex()


def verify_signature_ed25519(event: AuditEvent, public_key_bytes: bytes) -> bool:
    """Verify an event's Ed25519 asymmetric signature using a 32-byte public key."""
    if not event.signature or not event.signature.startswith("ed25519:"):
        return False
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    try:
        sig_bytes = bytes.fromhex(event.signature[len("ed25519:"):])
        pub = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(sig_bytes, event.event_hash.encode("ascii"))
        return True
    except (ValueError, InvalidSignature):
        return False


def verify_signature(event: AuditEvent, key: bytes) -> bool:
    """True when the event carries a signature that matches its hash under ``key`` (HMAC or Ed25519)."""
    if not event.signature:
        return False
    if event.signature.startswith("ed25519:"):
        # If key is 32 bytes, it could be the public key or private key
        if len(key) == 32:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization
            try:
                # Try as public key first
                if verify_signature_ed25519(event, key):
                    return True
            except Exception:
                pass
            try:
                # Or derive public key from private key
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(key)
                pub_bytes = priv.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw
                )
                return verify_signature_ed25519(event, pub_bytes)
            except Exception:
                return False
        return False
    return hmac.compare_digest(event.signature, sign_event_hash(event.event_hash, key))
