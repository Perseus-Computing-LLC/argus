"""Optional bridge to the ``argus_ledger_native`` extension (bindings/python, pyo3).

When the extension is importable, :meth:`AppendOnlyLedger.verify_chain` runs the Rust
``ChainVerifier`` over the file's lines and reports ``verifier="native"``; otherwise, for an
HMAC-signed ledger (the Rust crate has no HMAC scheme), or when ``ARGUS_LEDGER_PURE_PYTHON=1``
is set, it runs the pure-Python loop and reports ``verifier="python"``. Both paths return the
same verdict, position and counts; the cross-verifier matrix test holds them to that."""

import os
from typing import Any, Dict, Iterable, Optional, Tuple

PURE_PYTHON_ENV = "ARGUS_LEDGER_PURE_PYTHON"

try:  # pragma: no cover - exercised only where the extension is built
    import argus_ledger_native as _ext
except ImportError:  # pragma: no cover
    _ext = None


def available() -> bool:
    """True if the extension module is importable in this interpreter."""
    return _ext is not None


def enabled() -> bool:
    """True if verification should go through the extension: importable and not opted out."""
    return available() and os.environ.get(PURE_PYTHON_ENV, "").strip().lower() not in ("1", "true", "yes")


def verify_lines(
    lines: Iterable[str],
    *,
    anchor: Optional[Tuple[int, str]] = None,
    verifying_key: Optional[bytes] = None,
    legacy_timestamps_before: Optional[int] = None,
) -> Dict[str, Any]:
    """Run the Rust verifier over non-blank record lines in file order; see the extension docs."""
    if _ext is None:
        raise RuntimeError("argus_ledger_native is not installed")
    return _ext.verify_lines(
        lines, anchor=anchor, verifying_key=verifying_key, legacy_timestamps_before=legacy_timestamps_before
    )


def canonical_json_line(line: str) -> str:
    """Parse one record with the Rust parser and re-serialise it with ``AuditEvent::to_json_line``."""
    if _ext is None:
        raise RuntimeError("argus_ledger_native is not installed")
    return _ext.canonical_json_line(line)


def crate_version() -> str:
    if _ext is None:
        raise RuntimeError("argus_ledger_native is not installed")
    return _ext.crate_version()
