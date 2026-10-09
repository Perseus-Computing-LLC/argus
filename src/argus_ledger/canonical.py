"""RFC-8785 JSON canonicalization for deterministic cryptographic hashing."""

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
