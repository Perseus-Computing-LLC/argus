"""G-B (issue #15): the Python package verifies through the Rust `ChainVerifier` when the
`argus_ledger_native` extension is importable, and falls back to the pure-Python loop when it
is not or when the ledger is HMAC-signed (the Rust crate has no HMAC scheme).

The extension lives in bindings/python and is built with `maturin develop` (CI) or installed
as a wheel. Without it these tests skip on a developer machine and fail in CI (CI=true), the
same rule as the cross-verifier matrix, so a missing build can never pass as agreement.
"""

import json
import os
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

from argus_ledger import AppendOnlyLedger, ChainAnchor
from argus_ledger import _native
from test_cross_verifier_matrix import _cases, _skip_or_fail

PURE = "ARGUS_LEDGER_PURE_PYTHON"
REPORT_FIELDS = (
    "valid", "total_events", "root_hash", "head_hash", "first_broken_sequence",
    "legacy_events", "legacy_timestamp_regressions", "warnings", "anchored",
)


def _write(path, n=3, **kw):
    ledger = AppendOnlyLedger(path, **kw)
    for i in range(n):
        ledger.append("tool.exec", "worker_1", {"step": i, "max": 2**53 - 1})
    return ledger


def _mutate(path, case):
    mutate, expected = _cases()[case]
    with open(path, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    records, trailer = mutate(records)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records))
        fh.write(trailer)
    return expected


class NativeVerifierTest(unittest.TestCase):
    def setUp(self):
        if not _native.available():
            _skip_or_fail(self, "argus_ledger_native extension not built (bindings/python, maturin develop)")
        self.dir = tempfile.mkdtemp(prefix="argus_native_")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        os.environ.pop(PURE, None)

    def _path(self, name):
        return os.path.join(self.dir, f"{name}.jsonl")

    def _both(self, path, **kw):
        """(native report, pure-Python report) for the same file and arguments; warnings captured."""
        with warnings.catch_warnings(record=True) as native_w:
            warnings.simplefilter("always")
            native = AppendOnlyLedger(path, **{k: v for k, v in kw.items() if k in ("verify_key", "signing_key", "use_ed25519")}).verify_chain(
                **{k: v for k, v in kw.items() if k in ("anchor", "legacy_timestamps_before")})
        with mock.patch.dict(os.environ, {PURE: "1"}), warnings.catch_warnings(record=True) as pure_w:
            warnings.simplefilter("always")
            pure = AppendOnlyLedger(path, **{k: v for k, v in kw.items() if k in ("verify_key", "signing_key", "use_ed25519")}).verify_chain(
                **{k: v for k, v in kw.items() if k in ("anchor", "legacy_timestamps_before")})
        self.assertEqual(len(native_w), len(native.warnings))
        self.assertEqual(len(pure_w), len(pure.warnings))
        return native, pure

    def _assert_same(self, native, pure, what):
        self.assertEqual({f: getattr(native, f) for f in REPORT_FIELDS},
                         {f: getattr(pure, f) for f in REPORT_FIELDS}, what)
        self.assertEqual(native.error_detail is None, pure.error_detail is None, what)

    # --- dispatch --------------------------------------------------------------------------

    def test_verify_chain_uses_the_native_verifier_when_available(self):
        path = self._path("dispatch")
        _write(path)
        with mock.patch.object(_native, "verify_lines", wraps=_native.verify_lines) as spy:
            report = AppendOnlyLedger(path).verify_chain()
        self.assertTrue(report.valid, report.error_detail)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual(report.verifier, "native")

    def test_env_override_forces_the_pure_python_loop(self):
        path = self._path("override")
        _write(path)
        with mock.patch.dict(os.environ, {PURE: "1"}), mock.patch.object(_native, "verify_lines") as spy:
            report = AppendOnlyLedger(path).verify_chain()
        self.assertTrue(report.valid)
        spy.assert_not_called()
        self.assertEqual(report.verifier, "python")

    def test_hmac_signed_ledgers_stay_on_the_python_loop(self):
        path = self._path("hmac")
        key = b"0123456789abcdef0123456789abcdef"
        _write(path, signing_key=key)
        with mock.patch.object(_native, "verify_lines") as spy:
            report = AppendOnlyLedger(path, signing_key=key).verify_chain()
        self.assertTrue(report.valid, report.error_detail)
        spy.assert_not_called()
        self.assertEqual(report.verifier, "python")

    # --- agreement with the pure-Python loop on the adversarial matrix ----------------------

    def test_native_report_equals_pure_python_report_on_every_matrix_case(self):
        for case, (_, expected) in _cases().items():
            with self.subTest(case=case):
                path = self._path(case)
                _write(path)
                _mutate(path, case)
                native, pure = self._both(path)
                self._assert_same(native, pure, case)
                self.assertEqual((native.valid, native.first_broken_sequence), expected, case)
                self.assertEqual(native.verifier, "native")

    def test_parse_failure_keeps_the_python_wording(self):
        path = self._path("torn")
        _write(path)
        _mutate(path, "torn_tail")
        report = AppendOnlyLedger(path).verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 4)
        self.assertIn("Malformed or partial event record at sequence 4", report.error_detail)

    def test_legacy_cutoff_and_warnings_agree(self):
        path = self._path("legacy")
        _write(path, n=6)
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        # Rebuild records 3.. with the timestamp of record 2 repeated at 3 (a regression below the cutoff).
        from test_cross_verifier_matrix import _rechain
        records[2]["timestamp"] = records[1]["timestamp"]
        records, _ = _rechain(records, 2), ""
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))
        for cutoff, valid in ((None, False), (3, False), (4, True), (100, True)):
            with self.subTest(cutoff=cutoff):
                native, pure = self._both(path, legacy_timestamps_before=cutoff)
                self._assert_same(native, pure, f"cutoff={cutoff}")
                self.assertEqual(native.valid, valid)
                if valid:
                    self.assertEqual(native.legacy_timestamp_regressions, 1)
                    self.assertEqual(len(native.warnings), 1)
                    self.assertEqual(native.warnings, pure.warnings)
        for bad in (0, -1, True, "3"):
            with self.subTest(bad=bad), self.assertRaises((TypeError, ValueError)):
                AppendOnlyLedger(path).verify_chain(legacy_timestamps_before=bad)

    def test_anchor_agrees(self):
        path = self._path("anchor")
        ledger = _write(path)
        head = list(ledger.iter_events())[-1]
        good = ChainAnchor(sequence=head.sequence, event_hash=head.event_hash)
        wrong = ChainAnchor(sequence=head.sequence, event_hash="0" * 64)
        beyond = ChainAnchor(sequence=99, event_hash=head.event_hash)
        for name, anchor, valid, broken in (("good", good, True, None), ("wrong", wrong, False, 3), ("beyond", beyond, False, 99)):
            with self.subTest(anchor=name):
                native, pure = self._both(path, anchor=anchor)
                self._assert_same(native, pure, name)
                self.assertEqual((native.valid, native.first_broken_sequence, native.anchored), (valid, broken, True))

    def test_ed25519_signatures_agree(self):
        from argus_ledger.hasher import ed25519_public_key
        path = self._path("ed25519")
        seed = bytes(range(32))
        _write(path, signing_key=seed, use_ed25519=True)
        pub = ed25519_public_key(seed)
        native, pure = self._both(path, verify_key=pub)
        self._assert_same(native, pure, "signed")
        self.assertTrue(native.valid, native.error_detail)
        self.assertEqual(native.verifier, "native")
        # Strip the signature from record 2: both verifiers fail at 2.
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        records[1]["signature"] = None
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in records))
        native, pure = self._both(path, verify_key=pub)
        self._assert_same(native, pure, "stripped")
        self.assertEqual((native.valid, native.first_broken_sequence), (False, 2))
        # The wrong key fails at 1.
        native, pure = self._both(path, verify_key=ed25519_public_key(bytes(range(1, 33))))
        self._assert_same(native, pure, "wrong key")
        self.assertEqual((native.valid, native.first_broken_sequence), (False, 1))

    # --- to_json_line parity (issue #15) ---------------------------------------------------

    def test_canonical_json_line_round_trips_python_records(self):
        path = self._path("canon")
        _write(path)
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            native_line = _native.canonical_json_line(line)
            self.assertEqual(json.loads(native_line), json.loads(line))
            self.assertNotIn("\n", native_line)
        with self.assertRaises(ValueError):
            _native.canonical_json_line('{"sequence":1,"tim')

    def test_native_reports_its_crate_version(self):
        self.assertRegex(_native.crate_version(), r"^\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
