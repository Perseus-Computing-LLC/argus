"""Cross-language compatibility tests between Python argus_ledger and Rust FileLedger."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from argus_ledger import AppendOnlyLedger
from argus_ledger.hasher import compute_event_hash, compute_payload_digest
from argus_ledger.models import GENESIS_PREV_HASH


def _find_rust_tools() -> tuple[str, Path, Path] | None:
    rustc = os.environ.get("RUSTC") or shutil.which("rustc")
    if not rustc and os.path.isfile("/opt/data/home/.cargo/bin/rustc"):
        rustc = "/opt/data/home/.cargo/bin/rustc"
    if not rustc or not shutil.which(rustc):
        return None

    repo_root = Path(__file__).resolve().parent.parent
    rlibs = list(repo_root.glob("target/**/libargus_ledger.rlib"))
    if not rlibs:
        return None

    # Prefer release over debug if available
    rlib = next((r for r in rlibs if "release" in r.parts), rlibs[0])
    deps_dir = rlib.parent / "deps"
    return rustc, rlib, deps_dir


class TestFileLedgerCrossCompat(unittest.TestCase):
    def test_golden_hash_parity_with_rust(self):
        # 1. Payload digest parity
        d1 = compute_payload_digest({"command": "build"})
        self.assertEqual(d1, "e053d91e793d447a4d3c889162d6303593a89b5c9323850ffcaa6465e5b42345")

        d_empty = compute_payload_digest({})
        self.assertEqual(d_empty, "98db375430d9d7e035552d94f599855e44b9257f5151438a065fa59c583ec93a")

        # 2. Event hash parity
        h1 = compute_event_hash(
            sequence=1,
            event_id="ev_0123456789abcdef0123456789abcdef_1",
            timestamp="1760659200000000000",
            event_type="tool.exec",
            actor="arn:aws:iam::123456789012:user/alice",
            prev_hash=GENESIS_PREV_HASH,
            payload={"command": "build"},
            hash_version=2,
        )
        self.assertEqual(h1, "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b")

    def test_python_writes_rust_verifies(self):
        tools = _find_rust_tools()
        if tools is None:
            self.skipTest("rustc or compiled libargus_ledger.rlib not available")
        rustc, rlib, deps_dir = tools

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        rs_src = path.replace(".jsonl", "_runner.rs")
        rs_bin = path.replace(".jsonl", "_runner.bin")
        try:
            py_ledger = AppendOnlyLedger(path)
            py_ledger.append("agent.startup", "coordinator", {"status": "ok"})
            py_ledger.append("tool.exec", "worker_1", {"command": "cargo test"})

            code = f"""
            extern crate argus_ledger;
            use argus_ledger::{{AuditLedgerReader, AuditVerifier, FileLedger}};
            fn main() {{
                let ledger = FileLedger::new("{path}").unwrap();
                let events = ledger.all_events().unwrap();
                assert_eq!(events.len(), 2);
                let report = ledger.verify_chain().unwrap();
                assert!(report.valid);
            }}
            """
            with open(rs_src, "w") as f:
                f.write(code)

            cmd = [
                rustc,
                "--edition=2021",
                "--crate-name=verify_runner",
                f"--extern=argus_ledger={rlib}",
            ]
            if deps_dir.is_dir():
                cmd.extend(["-L", str(deps_dir)])
            cmd.extend([rs_src, "-o", rs_bin])

            subprocess.check_output(cmd)
            subprocess.check_call([rs_bin])
        finally:
            for p in (path, rs_src, rs_bin):
                if os.path.exists(p):
                    os.remove(p)

    def test_python_float_payload_verifies_with_argus_verify(self):
        """A float the Python writer prints with 16 digits must hash the same in the Rust verifier."""
        binary = shutil.which("argus-verify")
        for candidate in (Path(__file__).resolve().parents[1] / "target" / "release" / "argus-verify",
                          Path(__file__).resolve().parents[1] / "target" / "debug" / "argus-verify"):
            if candidate.is_file():
                binary = str(candidate)
                break
        if not binary:
            self.skipTest("argus-verify binary not built")
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            ledger = AppendOnlyLedger(path)
            ledger.append("tool_execution", "hermes_agent", {"tool": "kibisis_recall", "top_score": -9.865914147294541})
            ledger.append("tool_execution", "hermes_agent", {"ratio": 0.1 + 0.2, "half": 0.5, "neg": -1234.5678})
            self.assertTrue(ledger.verify_chain().valid)
            run = subprocess.run([binary, "--json", path], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('"valid":true', run.stdout)
        finally:
            if os.path.exists(path):
                os.remove(path)

    @unittest.expectedFailure
    def test_python_exponent_float_payload_known_gap(self):
        """Known parity gap: Python repr writes `1e-07` / `1e+308`, serde_json writes `1e-7` / `1e308`.

        The Python writer should refuse floats (as the Rust writer does) or format them the Rust
        way; until then a ledger with exponent-form floats verifies in Python but not in Rust.
        """
        binary = shutil.which("argus-verify")
        for candidate in (Path(__file__).resolve().parents[1] / "target" / "release" / "argus-verify",
                          Path(__file__).resolve().parents[1] / "target" / "debug" / "argus-verify"):
            if candidate.is_file():
                binary = str(candidate)
                break
        if not binary:
            self.skipTest("argus-verify binary not built")
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            ledger = AppendOnlyLedger(path)
            ledger.append("tool_execution", "hermes_agent", {"small": 1e-7, "big": 1.7976931348623157e308})
            run = subprocess.run([binary, "--json", path], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_rust_writes_python_verifies(self):
        tools = _find_rust_tools()
        if tools is None:
            self.skipTest("rustc or compiled libargus_ledger.rlib not available")
        rustc, rlib, deps_dir = tools

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        rs_src = path.replace(".jsonl", "_runner.rs")
        rs_bin = path.replace(".jsonl", "_runner.bin")
        try:
            code = f"""
            extern crate argus_ledger;
            use argus_ledger::{{AuditLedgerWriter, FileLedger}};
            fn main() {{
                let ledger = FileLedger::new("{path}").unwrap();
                ledger.append("agent.startup", "coordinator", r#"{{"status":"ok"}}"#).unwrap();
                ledger.append("tool.exec", "worker_1", r#"{{"command":"test"}}"#).unwrap();
            }}
            """
            with open(rs_src, "w") as f:
                f.write(code)

            cmd = [
                rustc,
                "--edition=2021",
                "--crate-name=write_runner",
                f"--extern=argus_ledger={rlib}",
            ]
            if deps_dir.is_dir():
                cmd.extend(["-L", str(deps_dir)])
            cmd.extend([rs_src, "-o", rs_bin])

            subprocess.check_output(cmd)
            subprocess.check_call([rs_bin])

            py_ledger = AppendOnlyLedger(path)
            report = py_ledger.verify_chain()
            self.assertTrue(report.valid)
            self.assertEqual(report.total_events, 2)
        finally:
            for p in (path, rs_src, rs_bin):
                if os.path.exists(p):
                    os.remove(p)


if __name__ == "__main__":
    unittest.main()
