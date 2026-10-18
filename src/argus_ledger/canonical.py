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


def canonical_json_bytes(obj: Any) -> bytes:
    """Return UTF-8 encoded bytes for canonical JSON serialization."""
    return canonical_json_dumps(obj).encode("utf-8")
