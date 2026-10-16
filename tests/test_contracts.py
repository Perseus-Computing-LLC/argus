"""Unit tests for Argus tamper-evident append-only ledger and hash verification."""

import json
import os
import tempfile
import unittest
from argus_ledger import (
    AppendOnlyLedger,
    AuditEvent,
    ChainVerificationReport,
    GENESIS_PREV_HASH,
    LedgerCorruptionError,
    canonical_json_dumps,
    compute_event_hash,
)


class TestArgusContracts(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ledger_file = os.path.join(self.tmp_dir.name, "audit.jsonl")
        self.ledger = AppendOnlyLedger(self.ledger_file)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_canonical_json_determinism(self):
        d1 = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
        d2 = {"a": 2, "m": {"a": 4, "b": 3}, "z": 1}
        self.assertEqual(canonical_json_dumps(d1), canonical_json_dumps(d2))
        self.assertEqual(canonical_json_dumps(d1), '{"a":2,"m":{"a":4,"b":3},"z":1}')

    def test_append_and_chain_verification(self):
        ev1 = self.ledger.append(
            event_type="agent.session.start",
            actor="hermes_agent",
            payload={"session_id": "sess_1001", "model": "gemini-3.8-flash"},
        )
        self.assertEqual(ev1.sequence, 1)
        self.assertEqual(ev1.prev_hash, GENESIS_PREV_HASH)

        ev2 = self.ledger.append(
            event_type="tool.exec",
            actor="hermes_agent",
            payload={"tool": "kibisis_remember", "args": {"key": "rule_1"}},
        )
        self.assertEqual(ev2.sequence, 2)
        self.assertEqual(ev2.prev_hash, ev1.event_hash)

        ev3 = self.ledger.append(
            event_type="context.prune",
            actor="harpe_engine",
            payload={"pruned_tokens": 150, "consumed_tokens": 850},
        )
        self.assertEqual(ev3.sequence, 3)
        self.assertEqual(ev3.prev_hash, ev2.event_hash)

        # Verification report
        report = self.ledger.verify_chain()
        self.assertTrue(report.valid)
        self.assertEqual(report.total_events, 3)
        self.assertEqual(report.head_hash, ev3.event_hash)
        self.assertEqual(report.root_hash, ev1.event_hash)

    def test_tampering_detection(self):
        # Append 3 events
        self.ledger.append("event.1", "actor", {"val": 1})
        self.ledger.append("event.2", "actor", {"val": 2})
        self.ledger.append("event.3", "actor", {"val": 3})

        report_clean = self.ledger.verify_chain()
        self.assertTrue(report_clean.valid)

        # Tamper with event 2 in the ledger file
        lines = []
        with open(self.ledger_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f]

        lines[1]["payload"]["val"] = 999  # Malicious alteration

        with open(self.ledger_file, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(json.dumps(l) + "\n")

        # Verify should now detect tampering at sequence 2
        report_tampered = self.ledger.verify_chain()
        self.assertFalse(report_tampered.valid)
        self.assertEqual(report_tampered.first_broken_sequence, 2)

    def test_partial_write_and_malformed_record_fail_closed(self):
        self.ledger.append("event.1", "actor", {"val": 1})
        self.ledger.append("event.2", "actor", {"val": 2})

        # Simulate a truncated partial write at sequence 3
        with open(self.ledger_file, "a", encoding="utf-8") as f:
            f.write('{"sequence": 3, "event_id": "partial-crash\n')

        report = self.ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 3)
        self.assertIn("Malformed or partial event record", report.error_detail or "")

        with self.assertRaises(LedgerCorruptionError):
            self.ledger.head()
        with self.assertRaises(LedgerCorruptionError):
            self.ledger.append("event.4", "actor", {"val": 4})


if __name__ == "__main__":
    unittest.main()
