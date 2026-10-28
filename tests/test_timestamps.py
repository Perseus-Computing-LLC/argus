"""F5: the Python writer's monotonic guard and the shared instant parser."""
import os
import tempfile
import unittest
from unittest import mock

from argus_ledger import AppendOnlyLedger
from argus_ledger.timestamps import timestamp_nanos

T = 1_793_145_600_000_000_000  # 2026-10-28T00:00:00Z


class TimestampParserTest(unittest.TestCase):
    def test_forms_and_offsets_parse_to_the_same_instant(self):
        cases = {
            "1793145600000000000": T,
            "2026-10-28T00:00:00+00:00": T,
            "2026-10-28T00:00:00Z": T,
            "2026-10-28T00:00:00": T,
            "2026-10-28T05:00:00+05:00": T,
            "2026-10-27T19:30:00-04:30": T,
            "2026-10-28T00:00:00.123456+00:00": T + 123_456_000,
            "2026-10-28T00:00:00.123456789Z": T + 123_456_789,
            "2026-10-28T00:00:00.1234567891Z": T + 123_456_789,
            "2026-10-28T00:00:00.+00:00": None,
            "2026-10-28T00:00:00+0500": None,
            "2026-10-28T00:00:00+15:00": None,
            "2026-10-28T00:00:00+05:60": None,
            "2026-10-28T00:00:00x": None,
            "2026-13-28T00:00:00Z": None,
            "01793145600000000000": None,
            "": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(timestamp_nanos(text), expected)
        self.assertLess(timestamp_nanos("2026-10-28T04:59:59+05:00"), timestamp_nanos("2026-10-28T00:00:00+00:00"))


class MonotonicWriterTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="argus_ts_")
        self.path = os.path.join(self.dir, "audit.jsonl")

    def test_clock_stepping_backwards_still_yields_increasing_instants(self):
        import datetime

        ledger = AppendOnlyLedger(self.path)
        first = ledger.append("tool.exec", "agent", {"i": 1})
        past = datetime.datetime.fromisoformat(first.timestamp) - datetime.timedelta(hours=1)

        class SteppedBack(datetime.datetime):
            @classmethod
            def now(cls, tz=None):
                return past.astimezone(tz) if tz else past

        with mock.patch("argus_ledger.ledger.datetime.datetime", SteppedBack):
            second = ledger.append("tool.exec", "agent", {"i": 2})
        self.assertEqual(timestamp_nanos(second.timestamp), timestamp_nanos(first.timestamp) + 1000)
        self.assertTrue(second.timestamp.endswith("+00:00"), second.timestamp)
        self.assertTrue(ledger.verify_chain().valid)

    def test_after_a_rust_nanosecond_record_the_next_microsecond_is_used(self):
        # A Rust-written tail record in the far future with a non-zero nanosecond part.
        from argus_ledger.hasher import compute_event_hash
        from argus_ledger.models import GENESIS_PREV_HASH
        import json

        ts = "16725225600000000123"  # 2500-01-01T00:00:00.000000123Z
        rec = {"sequence": 1, "event_id": "rs-1", "timestamp": ts, "event_type": "tool.exec", "actor": "a",
               "payload": {}, "prev_hash": GENESIS_PREV_HASH, "signature": None, "hash_version": 2}
        rec["event_hash"] = compute_event_hash(1, "rs-1", ts, "tool.exec", "a", GENESIS_PREV_HASH, {})
        with open(self.path, "w") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        ledger = AppendOnlyLedger(self.path)
        second = ledger.append("tool.exec", "a", {})
        self.assertEqual(second.timestamp, "2500-01-01T00:00:00.000001+00:00")
        self.assertGreater(timestamp_nanos(second.timestamp), int(ts))
        self.assertTrue(ledger.verify_chain().valid)

    def test_verify_rejects_equal_and_backdated_offsets(self):
        from argus_ledger.hasher import compute_event_hash
        from argus_ledger.models import GENESIS_PREV_HASH
        import json

        def rec(seq, ts, prev):
            r = {"sequence": seq, "event_id": f"e{seq}", "timestamp": ts, "event_type": "t.e", "actor": "a",
                 "payload": {}, "prev_hash": prev, "signature": None, "hash_version": 2}
            r["event_hash"] = compute_event_hash(seq, f"e{seq}", ts, "t.e", "a", prev, {})
            return r

        for second_ts, valid in [
            ("2026-10-28T05:00:01+05:00", True),   # one second later, other offset
            ("2026-10-28T05:00:00+05:00", False),  # same instant
            ("2026-10-28T04:00:00+05:00", False),  # textually later, earlier instant
            ("not-a-time", False),
        ]:
            with self.subTest(second_ts=second_ts):
                r1 = rec(1, "2026-10-28T00:00:00+00:00", GENESIS_PREV_HASH)
                r2 = rec(2, second_ts, r1["event_hash"])
                with open(self.path, "w") as fh:
                    fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in (r1, r2)))
                report = AppendOnlyLedger(self.path).verify_chain()
                self.assertEqual(report.valid, valid, report.error_detail)
                if not valid:
                    self.assertEqual(report.first_broken_sequence, 2)


if __name__ == "__main__":
    unittest.main()
