"""Deterministic JSON canonicalization for cryptographic hashing.

Output: keys sorted by code point, compact separators, UTF-8 without ASCII escaping, and no NaN or
Infinity. For objects whose numbers are integers within +/-(2**53 - 1), these are exactly the bytes
the Rust crate's ``validate_canonical_payload`` accepts. The form differs from RFC 8785 for floats
and for object keys that mix U+E000..U+FFFF with non-BMP characters (code-point versus UTF-16 order).
"""

from __future__ import annotations

import json
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


class FloatPayloadError(ValueError):
    """A payload holds an IEEE-754 float; the two writers would not agree on its text."""


def reject_float_payload(obj: Any, path: str = "payload") -> None:
    """Refuse ``float`` anywhere in a payload, as the Rust writer's ``validate_canonical_payload`` does.

    Python prints the shortest round-trip repr (``-9.865914147294541``, ``1e-07``); serde_json prints
    ``1e-7`` and, without the ``float_roundtrip`` feature, parses 16-17 digit values inexactly. Either
    difference changes the payload digest, so the verifier on one side rejects what the other wrote.
    Callers pass integers (basis points, micro-units, milliseconds) or fixed-format strings instead.
    """
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, float):
        raise FloatPayloadError(
            f"{path} is a float ({obj!r}); store an integer (e.g. basis points or micro-units) or a "
            f"fixed-format string such as f\"{{x:.6f}}\" so Python and Rust hash the same bytes"
        )
    if isinstance(obj, dict):
        for k, v in obj.items():
            reject_float_payload(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            reject_float_payload(v, f"{path}[{i}]")


def canonical_json_bytes(obj: Any) -> bytes:
    """Return UTF-8 encoded bytes for canonical JSON serialization."""
    return canonical_json_dumps(obj).encode("utf-8")
