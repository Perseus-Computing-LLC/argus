"""Record timestamps as instants.

The contract, enforced by every verifier (this package, the Rust crate, ``argus-verify``): within
a ledger, timestamps are strictly increasing when compared as instants. A record is written in one
of two forms and both are read by every verifier:

* canonical decimal nanoseconds since the UNIX epoch (the Rust writers), or
* RFC 3339 date-time with an explicit UTC offset, ``Z`` or no suffix meaning UTC (this package
  writes ``+00:00`` with microsecond resolution).

``timestamp_nanos`` is the single parser; it mirrors ``parse_timestamp_nanos`` in the Rust crate
(same grammar, same bounds, fraction truncated to nanoseconds) so the two sides never disagree
about which records are ordered.
"""

from __future__ import annotations

import calendar
import re
from typing import Optional

_CANONICAL_INT = re.compile(r"^(0|[1-9][0-9]*)$")
_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?$"
)
_U64_MAX = 2**64 - 1


def timestamp_nanos(value: str) -> Optional[int]:
    """Return nanoseconds since the epoch for a record timestamp, or None if malformed."""
    if not isinstance(value, str):
        return None
    if _CANONICAL_INT.match(value):
        n = int(value)
        return n if n <= _U64_MAX else None
    m = _ISO.match(value)
    if m is None:
        return None
    year, month, day, hour, minute, second = (int(x) for x in m.group(1, 2, 3, 4, 5, 6))
    frac, offset = m.group(7), m.group(8)
    # Same bounds as the Rust parser: a leap second (60) is accepted, day 31 is not checked
    # against the month, and offsets up to +/-14:59 are allowed.
    if not (1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 60):
        return None
    offset_secs = 0
    if offset and offset != "Z":
        sign = 1 if offset[0] == "+" else -1
        hh, mm = int(offset[1:3]), int(offset[4:6])
        if hh > 14 or mm > 59:
            return None
        offset_secs = sign * (hh * 3600 + mm * 60)
    # calendar.timegm accepts day 31 of any month and second 60 by arithmetic, as the Rust
    # days-from-civil routine does.
    local_secs = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    epoch_secs = local_secs - offset_secs
    if epoch_secs < 0:
        return None
    nanos = int((frac or "0")[:9].ljust(9, "0"))
    total = epoch_secs * 1_000_000_000 + nanos
    return total if total <= _U64_MAX else None
