"""Unit tests for Argus ledger ergonomics, properties, and alias compatibility."""

import os
import tempfile
import unittest

from argus_ledger import AppendOnlyLedger
import argus


class TestArgusLedgerErgonomics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.ledger_path = self.tmp.name
        self.tmp.close()

    def tearDown(self):
        if os.path.exists(self.ledger_path):
            os.unlink(self.ledger_path)

    def test_empty_ledger_properties(self):
        ledger = AppendOnlyLedger(self.ledger_path)
        self.assertIsNone(ledger.head())
        self.assertIsNone(ledger.head_hash)
        self.assertIsNone(ledger.last_hash)
        self.assertEqual(ledger.current_sequence, 0)
        self.assertEqual(len(ledger), 0)

    def test_populated_ledger_properties(self):
        ledger = AppendOnlyLedger(self.ledger_path)
        ev1 = ledger.append(
            event_type="test.start",
            actor="test-runner",
            payload={"action": "init"},
        )
        self.assertEqual(ledger.current_sequence, 1)
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger.head_hash, ev1.event_hash)
        self.assertEqual(ledger.last_hash, ev1.event_hash)

        ev2 = ledger.append(
            event_type="test.step",
            actor="test-runner",
            payload={"step": 2},
        )
        self.assertEqual(ledger.current_sequence, 2)
        self.assertEqual(len(ledger), 2)
        self.assertEqual(ledger.head_hash, ev2.event_hash)
        self.assertEqual(ledger.last_hash, ev2.event_hash)

    def test_import_argus_compatibility(self):
        self.assertTrue(hasattr(argus, "AppendOnlyLedger"))
        ledger = argus.AppendOnlyLedger(self.ledger_path)
        ev = ledger.append("alias.test", "actor", {"ok": True})
        self.assertEqual(ledger.head_hash, ev.event_hash)


if __name__ == "__main__":
    unittest.main()
