"""Deterministic JSON canonicalization for cryptographic hashing.

Output: keys sorted by code point, compact separators, UTF-8 without ASCII escaping, and no NaN or
Infinity. For objects whose numbers are integers within +/-(2**53 - 1), these are exactly the bytes
the Rust crate's ``validate_canonical_payload`` accepts. The form differs from RFC 8785 for floats
and for object keys that mix U+E000..U+FFFF with non-BMP characters (code-point versus UTF-16 order).
"""

from __future__ import annotations

import json
import re
from typing import Any


def canonical_json_dumps(obj: Any) -> str:
    """Serialize an object into deterministic canonical JSON (sorted keys, compact separators)."""
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


#: Same caps as the Rust crate (``MAX_IDENTIFIER_BYTES``, ``MAX_PAYLOAD_BYTES``, ``MAX_SAFE_INTEGER``).
MAX_IDENTIFIER_BYTES = 256
MAX_PAYLOAD_BYTES = 1 << 20
MAX_SAFE_INTEGER = 2**53 - 1

_EVENT_TYPE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")
# Printable ASCII without whitespace, quotes or backslashes: no control characters, log-line
# injection, Unicode homoglyphs, or JSON string syntax inside an identifier.
_ACTOR = re.compile(r"^[\x21-\x7e]+$")


class PayloadError(ValueError):
    """A payload the two writers would not hash identically, or that the Rust writer refuses."""


class FloatPayloadError(PayloadError):
    """A payload holds an IEEE-754 float; the two writers would not agree on its text."""


class IntegerRangeError(PayloadError):
    """A payload integer lies outside +/-(2**53 - 1); JSON readers do not agree beyond that."""


class IdentifierError(ValueError):
    """``event_type`` or ``actor`` violates the identifier grammar shared with the Rust crate."""


def validate_identifiers(event_type: str, actor: str) -> None:
    """Apply the Rust crate's ``validate_identifiers`` grammar.

    ``event_type``: dot-separated ``[a-z0-9_-]+`` segments. ``actor``: printable ASCII without
    whitespace, ``"`` or ``\\``. Both at most 256 bytes. The Rust writer has always refused
    anything else, so a Python-written record that Rust would not have produced is a parity
    gap, and an actor carrying JSON syntax or a newline is how one record becomes two.
    """
    if not isinstance(event_type, str) or len(event_type) > MAX_IDENTIFIER_BYTES or not _EVENT_TYPE.match(event_type):
        raise IdentifierError("event_type must be dot-separated [a-z0-9_-]+ segments (at most 256 bytes)")
    if (
        not isinstance(actor, str)
        or not actor
        or len(actor) > MAX_IDENTIFIER_BYTES
        or not _ACTOR.match(actor)
        or '"' in actor
        or "\\" in actor
    ):
        raise IdentifierError(
            "actor must be printable ASCII without whitespace, quotes or backslashes (1-256 bytes)"
        )


def _check_values(obj: Any, path: str) -> None:
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return
    if isinstance(obj, float):
        raise FloatPayloadError(
            f"{path} is a float ({obj!r}); store an integer (e.g. basis points or micro-units) or a "
            f"fixed-format string such as f\"{{x:.6f}}\" so Python and Rust hash the same bytes"
        )
    if isinstance(obj, int):
        # Beyond 2**53-1 JavaScript-style readers round, and serde_json without
        # arbitrary_precision cannot represent values past the i64/u64 range at all.
        if abs(obj) > MAX_SAFE_INTEGER:
            raise IntegerRangeError(f"{path} is {obj}; integers must lie within +/-{MAX_SAFE_INTEGER}")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _check_values(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _check_values(v, f"{path}[{i}]")


def validate_payload(obj: Any, path: str = "payload") -> None:
    """Refuse what the Rust writer's ``validate_canonical_payload`` refuses: a non-object, any
    ``float``, any integer outside +/-(2**53 - 1), or a canonical encoding over 1 MiB.

    Python prints the shortest round-trip repr (``-9.865914147294541``, ``1e-07``); serde_json prints
    ``1e-7`` and, without the ``float_roundtrip`` feature, parses 16-17 digit values inexactly. Either
    difference changes the payload digest, so the verifier on one side rejects what the other wrote.
    Callers pass integers (basis points, micro-units, milliseconds) or fixed-format strings instead.
    """
    if path == "payload" and not isinstance(obj, dict):
        raise PayloadError("payload must be a JSON object")
    _check_values(obj, path)
    if path == "payload" and len(canonical_json_bytes(obj)) > MAX_PAYLOAD_BYTES:
        raise PayloadError(f"payload exceeds {MAX_PAYLOAD_BYTES} canonical bytes")


#: Former name of :func:`validate_payload`, kept for callers that imported it.
reject_float_payload = validate_payload


def canonical_json_bytes(obj: Any) -> bytes:
    """Return UTF-8 encoded bytes for canonical JSON serialization."""
    return canonical_json_dumps(obj).encode("utf-8")
