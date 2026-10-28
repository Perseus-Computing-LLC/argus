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
use argus_ledger::{AuditLedgerWriter, AuditVerifier, FileLedger};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let ledger = FileLedger::new(&args[2]).unwrap();
    match args[1].as_str() {
        "write" => {
            ledger.append("agent.startup", "coordinator", r#"{"status":"ok"}"#).unwrap();
            ledger.append("tool.exec", "worker_1", r#"{"command":"test"}"#).unwrap();
            ledger.append("tool.exec", "worker_1", r#"{"max":9007199254740991,"min":-9007199254740991}"#).unwrap();
        }
        "verify" => {
            let r = ledger.verify_chain().unwrap();
            let pos = r.first_broken_sequence.map_or("null".to_string(), |p| p.to_string());
            println!("{{\"valid\":{},\"first_broken_sequence\":{},\"total_events\":{}}}", r.valid, pos, r.total_events);
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
            self.skipTest("Rust toolchain, libargus_ledger.rlib or argus-verify binary missing")
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


if __name__ == "__main__":
    unittest.main()
