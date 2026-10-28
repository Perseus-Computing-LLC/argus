"""F5: one timestamp contract, one malformed-line contract, across every writer and verifier.

Matrix: {Python writer, Rust writer} x {Python verify_chain, Rust FileLedger::verify_chain,
argus-verify CLI} over adversarial ledgers. Every cell must return the same verdict and the same
broken position. The Rust cells need rustc, a built libargus_ledger.rlib and the argus-verify
binary (CI builds the crate before pytest); without them the Rust cells are skipped, not passed.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from argus_ledger import AppendOnlyLedger
from argus_ledger.hasher import compute_event_hash
from argus_ledger.timestamps import timestamp_nanos

REPO = Path(__file__).resolve().parents[1]
MAX_SAFE_INT = 2**53 - 1


def _skip_or_fail(test, reason):
    """Skip on a developer machine without the Rust artifacts; fail in CI, where the workflow
    builds the crate first and a skip would hide a cross-language regression."""
    if os.environ.get("CI", "").lower() in ("1", "true"):
        test.fail(f"{reason} (CI must build the Rust crate before pytest)")
    test.skipTest(reason)



def _rustc():
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not rustc and os.path.isfile("/opt/data/home/.cargo/bin/rustc"):
        rustc = "/opt/data/home/.cargo/bin/rustc"
    return rustc if rustc and shutil.which(rustc) else None


def _rlib():
    rlibs = list(REPO.glob("target/**/libargus_ledger.rlib"))
    if not rlibs:
        return None
    return next((r for r in rlibs if "release" in r.parts), rlibs[0])


def _argus_verify():
    for candidate in (REPO / "target/release/argus-verify", REPO / "target/debug/argus-verify"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which("argus-verify")


RUNNER_SRC = r'''
extern crate argus_ledger;
use argus_ledger::{AuditLedgerWriter, AuditVerifier, FileLedger, VerificationPolicy};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ledger = FileLedger::new(&args[2]).unwrap();
    match args[1].as_str() {
        "write" => {
            ledger.append("agent.startup", "coordinator", r#"{"status":"ok"}"#).unwrap();
            ledger.append("tool.exec", "worker_1", r#"{"command":"test"}"#).unwrap();
            ledger.append("tool.exec", "worker_1", r#"{"max":9007199254740991,"min":-9007199254740991}"#).unwrap();
        }
        "write10" => {
            for i in 0..10 {
                ledger.append("tool.exec", "worker_1", &format!("{{\"step\":{i}}}")).unwrap();
            }
        }
        // "verify" takes an optional third argument: the --legacy-timestamps-before cutoff.
        "verify" => {
            let policy = VerificationPolicy {
                legacy_timestamps_before: args.get(3).map(|s| s.parse().unwrap()),
                ..Default::default()
            };
            let r = ledger.verify_chain_with(&policy).unwrap();
            let pos = r.first_broken_sequence.map_or("null".to_string(), |p| p.to_string());
            println!(
                "{{\"valid\":{},\"first_broken_sequence\":{},\"total_events\":{},\"legacy_timestamp_regressions\":{},\"warnings\":{}}}",
                r.valid, pos, r.total_events, r.legacy_timestamp_regressions, r.warnings.len()
            );
        }
        other => panic!("unknown mode {other}"),
    }
}
'''


def _ns(text: str) -> int:
    nanos = timestamp_nanos(text)
    assert nanos is not None, text
    return nanos


def _iso_with_offset(nanos: int, offset_minutes: int) -> str:
    """RFC 3339 text for an instant, expressed in a non-UTC offset with a 9-digit fraction."""
    import datetime

    local = nanos + offset_minutes * 60 * 1_000_000_000
    secs, frac = divmod(local, 1_000_000_000)
    dt = datetime.datetime.fromtimestamp(secs, datetime.timezone.utc)
    sign = "+" if offset_minutes >= 0 else "-"
    hh, mm = divmod(abs(offset_minutes), 60)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{frac:09d}{sign}{hh:02d}:{mm:02d}"


def _rechain(records, start_index=0):
    """Recompute event_hash and prev_hash from ``start_index`` so a mutation tests the rule under
    test (timestamp order, identifier content) rather than tripping the content hash first."""
    for i in range(start_index, len(records)):
        rec = records[i]
        rec["prev_hash"] = records[i - 1]["event_hash"] if i else rec["prev_hash"]
        rec["event_hash"] = compute_event_hash(
            rec["sequence"], rec["event_id"], rec["timestamp"], rec["event_type"], rec["actor"],
            rec["prev_hash"], rec["payload"], hash_version=rec.get("hash_version", 1),
        )
        rec["signature"] = None
    return records


# name -> (mutation(records) -> (records, trailing_text), expected (valid, first_broken))
def _cases():
    def equal_ts(r):
        r[1]["timestamp"] = r[0]["timestamp"]
        return _rechain(r, 1), ""

    def decreasing_ts(r):
        r[2]["timestamp"] = r[0]["timestamp"]
        return _rechain(r, 2), ""

    def plus5_same_instant(r):
        r[1]["timestamp"] = _iso_with_offset(_ns(r[1]["timestamp"]), 300)
        return _rechain(r, 1), ""

    def plus5_backdated(r):
        # Textually later than record 1 ("05:..." vs "00:..."), earlier as an instant.
        r[1]["timestamp"] = _iso_with_offset(_ns(r[0]["timestamp"]) - 1_000_000_000, 300)
        return _rechain(r, 1), ""

    def zulu(r):
        r[2]["timestamp"] = _iso_with_offset(_ns(r[2]["timestamp"]), 0).replace("+00:00", "Z")
        return _rechain(r, 2), ""

    def torn_tail(r):
        return r, '{"sequence":4,"event_id":"ev_4","tim'

    def empty_actor(r):
        r[1]["actor"] = ""
        return _rechain(r, 1), ""

    def big_ints(r):
        r[2]["payload"] = {"max": MAX_SAFE_INT, "min": -MAX_SAFE_INT, "zero": 0, "nested": [MAX_SAFE_INT]}
        return _rechain(r, 2), ""

    def blank_lines(r):
        return r, "\n\n"

    return {
        "base": (lambda r: (r, ""), (True, None)),
        "equal_timestamps": (equal_ts, (False, 2)),
        "decreasing_timestamps": (decreasing_ts, (False, 3)),
        "plus0500_same_instant": (plus5_same_instant, (True, None)),
        "plus0500_backdated": (plus5_backdated, (False, 2)),
        "zulu_suffix": (zulu, (True, None)),
        "torn_tail": (torn_tail, (False, 4)),
        # The identifier grammar is a writer-side gate; verifiers check what the hash commits to.
        "empty_actor": (empty_actor, (True, None)),
        "big_ints_at_the_safe_bound": (big_ints, (True, None)),
        "blank_lines_after_tail": (blank_lines, (True, None)),
    }


class CrossVerifierMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix="argus_matrix_")
        cls.runner = None
        cls.cli = _argus_verify()
        rustc, rlib = _rustc(), _rlib()
        if rustc and rlib:
            src = os.path.join(cls.dir, "runner.rs")
            binary = os.path.join(cls.dir, "runner")
            with open(src, "w") as fh:
                fh.write(RUNNER_SRC)
            cmd = [rustc, "--edition=2021", "--crate-name=matrix_runner", f"--extern=argus_ledger={rlib}"]
            if (rlib.parent / "deps").is_dir():
                cmd += ["-L", str(rlib.parent / "deps")]
            subprocess.check_output(cmd + [src, "-o", binary], stderr=subprocess.STDOUT)
            cls.runner = binary

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    # --- writers -------------------------------------------------------------------------

    def _write_python(self, path):
        ledger = AppendOnlyLedger(path)
        ledger.append("agent.startup", "coordinator", {"status": "ok"})
        ledger.append("tool.exec", "worker_1", {"command": "test"})
        ledger.append("tool.exec", "worker_1", {"max": MAX_SAFE_INT, "min": -MAX_SAFE_INT})

    def _write_rust(self, path):
        subprocess.check_call([self.runner, "write", path])

    # --- verifiers: each returns (valid, first_broken_sequence) -----------------------------

    def _verify_python(self, path):
        report = AppendOnlyLedger(path).verify_chain()
        return report.valid, report.first_broken_sequence

    def _verify_rust_lib(self, path):
        out = json.loads(subprocess.check_output([self.runner, "verify", path], text=True))
        return out["valid"], out["first_broken_sequence"]

    def _verify_cli(self, path):
        run = subprocess.run([self.cli, "--json", path], capture_output=True, text=True)
        out = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0 if out["valid"] else 1, run.stdout + run.stderr)
        return out["valid"], out.get("first_broken_sequence")

    # --- the matrix ------------------------------------------------------------------------

    def _ledgers(self):
        yield "python", self._write_python
        if self.runner:
            yield "rust", self._write_rust

    def _verifiers(self):
        yield "python", self._verify_python
        if self.runner:
            yield "rust_lib", self._verify_rust_lib
        if self.cli:
            yield "argus_verify", self._verify_cli

    def test_every_writer_and_verifier_agree_on_every_adversarial_ledger(self):
        verifiers = list(self._verifiers())
        writers = list(self._ledgers())
        if len(verifiers) < 3 or len(writers) < 2:
            _skip_or_fail(self, "Rust toolchain, libargus_ledger.rlib or argus-verify binary missing")
        cells = 0
        for writer_name, write in writers:
            for case_name, (mutate, expected) in _cases().items():
                with self.subTest(writer=writer_name, case=case_name):
                    path = os.path.join(self.dir, f"{writer_name}_{case_name}.jsonl")
                    if os.path.exists(path):
                        os.remove(path)
                    write(path)
                    with open(path, encoding="utf-8") as fh:
                        records = [json.loads(line) for line in fh if line.strip()]
                    self.assertEqual([r["sequence"] for r in records], [1, 2, 3])
                    records, trailer = mutate(records)
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write("".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records))
                        fh.write(trailer)
                    verdicts = {name: verify(path) for name, verify in verifiers}
                    self.assertEqual(verdicts, {name: expected for name in verdicts}, f"{writer_name}/{case_name}: {verdicts}")
                    cells += len(verdicts)
        self.assertEqual(cells, len(writers) * len(verifiers) * len(_cases()))

    # --- issue #14: accept-as-historic timestamp cutoff -------------------------------------

    def _write_python10(self, path):
        ledger = AppendOnlyLedger(path)
        for i in range(10):
            ledger.append("tool.exec", "worker_1", {"step": i})

    def _write_rust10(self, path):
        subprocess.check_call([self.runner, "write10", path])

    # Each returns (valid, first_broken_sequence, legacy_timestamp_regressions, warning_count).

    def _verify_python_legacy(self, path, cutoff):
        import warnings as _warnings

        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            report = AppendOnlyLedger(path).verify_chain(legacy_timestamps_before=cutoff)
        self.assertEqual(len(caught), len(report.warnings), [str(w.message) for w in caught])
        return report.valid, report.first_broken_sequence, report.legacy_timestamp_regressions, len(report.warnings)

    def _verify_rust_lib_legacy(self, path, cutoff):
        cmd = [self.runner, "verify", path] + ([str(cutoff)] if cutoff is not None else [])
        out = json.loads(subprocess.check_output(cmd, text=True))
        return out["valid"], out["first_broken_sequence"], out["legacy_timestamp_regressions"], out["warnings"]

    def _verify_cli_legacy(self, path, cutoff):
        cmd = [self.cli, "--json"] + (["--legacy-timestamps-before", str(cutoff)] if cutoff is not None else []) + [path]
        run = subprocess.run(cmd, capture_output=True, text=True)
        out = json.loads(run.stdout)
        self.assertEqual(run.returncode, 0 if out["valid"] else 1, run.stdout + run.stderr)
        # The CLI prints each warning once to stderr as well as in the JSON array.
        self.assertEqual(run.stderr.count("warning:"), len(out["warnings"]), run.stderr)
        return out["valid"], out.get("first_broken_sequence"), out.get("legacy_timestamp_regressions", 0), len(out["warnings"])

    def _legacy_verifiers(self):
        yield "python", self._verify_python_legacy
        if self.runner:
            yield "rust_lib", self._verify_rust_lib_legacy
        if self.cli:
            yield "argus_verify", self._verify_cli_legacy

    def _ledgers10(self):
        yield "python", self._write_python10
        if self.runner:
            yield "rust", self._write_rust10

    def _write_mutated(self, writer_name, write, case_name, mutate):
        path = os.path.join(self.dir, f"{writer_name}_legacy_{case_name}.jsonl")
        if os.path.exists(path):
            os.remove(path)
        write(path)
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        self.assertEqual([r["sequence"] for r in records], list(range(1, 11)))
        records = mutate(records)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records))
        return path

    def test_legacy_timestamps_before_agrees_across_every_verifier(self):
        """A clock-step regression at sequence 5 of 10: every verifier fails without the cutoff,
        passes with cutoff 6 (one regression counted, one warning) and fails again with cutoff 5,
        because the regression is at the cutoff, where the strict rule applies."""
        verifiers = list(self._legacy_verifiers())
        writers = list(self._ledgers10())
        if len(verifiers) < 3 or len(writers) < 2:
            _skip_or_fail(self, "Rust toolchain, libargus_ledger.rlib or argus-verify binary missing")

        def regression_at_5(r):
            r[4]["timestamp"] = r[3]["timestamp"]
            return _rechain(r, 4)

        def tampered_payload_at_2(r):
            # No rechain: the content hash at 2 no longer matches, well below the cutoff.
            regression_at_5(r)
            r[1]["payload"] = {"step": 99}
            return r

        expectations = [
            ("regression_at_5", regression_at_5, None, (False, 5, 0, 0)),
            ("regression_at_5", regression_at_5, 6, (True, None, 1, 1)),
            ("regression_at_5", regression_at_5, 5, (False, 5, 0, 0)),
            ("tampered_payload_at_2", tampered_payload_at_2, 6, (False, 2, 0, 0)),
        ]
        cells = 0
        for writer_name, write in writers:
            for case_name, mutate, cutoff, expected in expectations:
                with self.subTest(writer=writer_name, case=case_name, cutoff=cutoff):
                    path = self._write_mutated(writer_name, write, case_name, mutate)
                    verdicts = {name: verify(path, cutoff) for name, verify in verifiers}
                    self.assertEqual(verdicts, {name: expected for name in verdicts}, f"{writer_name}/{case_name}/{cutoff}: {verdicts}")
                    cells += len(verdicts)
        self.assertEqual(cells, len(writers) * len(verifiers) * len(expectations))

    def test_legacy_timestamps_before_rejects_zero_everywhere(self):
        path = os.path.join(self.dir, "python_legacy_zero.jsonl")
        if os.path.exists(path):
            os.remove(path)
        self._write_python10(path)
        with self.assertRaises(ValueError):
            AppendOnlyLedger(path).verify_chain(legacy_timestamps_before=0)
        with self.assertRaises(TypeError):
            AppendOnlyLedger(path).verify_chain(legacy_timestamps_before="6")
        if self.cli:
            run = subprocess.run([self.cli, "--json", "--legacy-timestamps-before", "0", path], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
