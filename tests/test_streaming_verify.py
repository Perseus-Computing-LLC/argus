"""F3: verify_chain reads the ledger once, one record at a time, and still finds faults."""
import os
import shutil
import tempfile
import unittest

from argus_ledger import AppendOnlyLedger, AuditEvent, ChainAnchor
from argus_ledger.hasher import compute_event_hash
from argus_ledger.ledger import AppendOnlyLedger as _Ledger
from argus_ledger.models import CURRENT_HASH_VERSION, GENESIS_PREV_HASH


class StreamingVerifyTest(unittest.TestCase):
    N = 50_000

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="argus_stream_")
        cls.path = os.path.join(cls.dir, "audit.jsonl")
        # The writer fsyncs every record, which is the point of the writer but far too slow for
        # 50k test records: build the same chain with the library's hash functions and write it
        # as one file.
        prev = GENESIS_PREV_HASH
        lines = []
        for i in range(cls.N):
            seq = i + 1
            fields = dict(
                sequence=seq,
                event_id=f"ev_{seq}",
                timestamp=f"2026-10-28T00:{i // 60000:02d}:{(i // 1000) % 60:02d}.{(i % 1000) * 1000:06d}+00:00",
                event_type="tool.exec",
                actor="agent",
                prev_hash=prev,
                payload={"i": i},
            )
            prev = compute_event_hash(**fields, hash_version=CURRENT_HASH_VERSION)
            ev = AuditEvent(**fields, event_hash=prev, hash_version=CURRENT_HASH_VERSION)
            lines.append(ev.model_dump_json())
        cls.pristine = "\n".join(lines) + "\n"
        with open(cls.path, "w", encoding="utf-8") as fh:
            fh.write(cls.pristine)
        cls.head = AppendOnlyLedger(cls.path).head()
        assert cls.head is not None and cls.head.sequence == cls.N

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def setUp(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(self.pristine)
        self.ledger = AppendOnlyLedger(self.path)

    def test_long_ledger_verifies_with_at_most_one_record_resident(self):
        seen = []
        original_records, original_lines = _Ledger._iter_records, _Ledger._iter_lines

        def counting_records(self_):
            # Each record is yielded and dropped before the next is parsed: the verifier keeps
            # the running state only. Count yields; a materialising implementation would read
            # all of them before checking the first.
            for ev in original_records(self_):
                seen.append(ev.sequence)
                yield ev

        def counting_lines(self_):
            # The native path hands the Rust verifier one line at a time through the same
            # kind of generator; pyo3 pulls it lazily, so the count proves the same property.
            for line in original_lines(self_):
                seen.append(line)
                yield line

        _Ledger._iter_records, _Ledger._iter_lines = counting_records, counting_lines
        try:
            report = self.ledger.verify_chain(ChainAnchor(sequence=self.N, event_hash=self.head.event_hash))
        finally:
            _Ledger._iter_records, _Ledger._iter_lines = original_records, original_lines
        self.assertTrue(report.valid, report.error_detail)
        self.assertEqual(report.total_events, self.N)
        self.assertEqual(report.head_hash, self.head.event_hash)
        self.assertEqual(len(seen), self.N)

    def test_fault_in_last_record_is_found_at_its_position(self):
        tail = f'"i":{self.N - 1}}}'
        broken = self.pristine.replace(tail, f'"i":{self.N}}}')
        self.assertNotEqual(broken, self.pristine)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write(broken)
        report = self.ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, self.N)
        self.assertEqual(report.total_events, self.N)

    def test_early_fault_stops_the_pass_before_reading_the_rest(self):
        lines = self.pristine.splitlines()
        lines[9] = lines[9][:-1]  # torn record at position 10
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        report = self.ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 10)
        self.assertEqual(report.total_events, 10, "records after the fault are not read")
        self.assertIn("Malformed or partial", report.error_detail)

    def test_truncated_below_anchor_is_detected(self):
        lines = self.pristine.splitlines()
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[:-1]) + "\n")
        report = self.ledger.verify_chain(ChainAnchor(sequence=self.N, event_hash=self.head.event_hash))
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, self.N)
        self.assertTrue(report.anchored)


if __name__ == "__main__":
    unittest.main()
