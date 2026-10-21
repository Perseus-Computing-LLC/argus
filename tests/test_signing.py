"""Keyed signing and file-permission contract for the Argus ledger."""

import json
import os
import stat
import tempfile
import unittest

from argus_ledger import AppendOnlyLedger, compute_event_hash, sign_event_hash, sign_event_hash_ed25519, verify_signature

KEY = b"k" * 32


def _rewrite_chain_without_key(path, edit_seq, new_payload):
    """The attack the unkeyed chain cannot detect: change one event and recompute every later hash."""
    with open(path, encoding="utf-8") as fh:
        events = [json.loads(l) for l in fh if l.strip()]
    prev = "0" * 64
    for ev in events:
        if ev["sequence"] == edit_seq:
            ev["payload"] = new_payload
        ev["prev_hash"] = prev
        ev["event_hash"] = compute_event_hash(ev["sequence"], ev["event_id"], ev["timestamp"], ev["event_type"], ev["actor"], prev, ev["payload"])
        prev = ev["event_hash"]
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")


class TestSigning(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def _fill(self, ledger, n=5):
        for i in range(n):
            ledger.append("tool_execution", "agent", {"i": i})

    def test_ledger_file_is_owner_only(self):
        AppendOnlyLedger(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_unkeyed_chain_misses_a_full_rewrite(self):
        """Documents the known limit of an unkeyed chain, so the keyed test below means something."""
        ledger = AppendOnlyLedger(self.path)
        self._fill(ledger)
        _rewrite_chain_without_key(self.path, 3, {"i": "forged"})
        self.assertTrue(ledger.verify_chain().valid)

    def test_keyed_chain_detects_a_full_rewrite(self):
        ledger = AppendOnlyLedger(self.path, signing_key=KEY)
        self._fill(ledger)
        self.assertTrue(ledger.verify_chain().valid)
        _rewrite_chain_without_key(self.path, 3, {"i": "forged"})
        report = ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 3)      # events 1-2 are unchanged; the first forged event is where it fails
        self.assertIn("signature", report.error_detail.lower())

    def test_signature_is_hmac_of_event_hash(self):
        ledger = AppendOnlyLedger(self.path, signing_key=KEY)
        ev = ledger.append("t", "a", {"x": 1})
        self.assertEqual(ev.signature, sign_event_hash(ev.event_hash, KEY))

    def test_wrong_key_fails_verification(self):
        self._fill(AppendOnlyLedger(self.path, signing_key=KEY))
        self.assertFalse(AppendOnlyLedger(self.path, signing_key=b"z" * 32).verify_chain().valid)

    def test_unsigned_events_fail_when_a_key_is_configured(self):
        self._fill(AppendOnlyLedger(self.path), 2)
        self.assertFalse(AppendOnlyLedger(self.path, signing_key=KEY).verify_chain().valid)

    def test_require_signature_refuses_to_open_without_key(self):
        with self.assertRaises(ValueError):
            AppendOnlyLedger(self.path, require_signature=True)

    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            AppendOnlyLedger(self.path, signing_key=b"short")

    def test_load_key_refuses_loose_permissions(self):
        kf = os.path.join(self.tmp.name, "key")
        with open(os.open(kf, os.O_WRONLY | os.O_CREAT, 0o644), "wb") as fh:
            fh.write(KEY)
        os.chmod(kf, 0o644)
        with self.assertRaises(PermissionError):
            AppendOnlyLedger.load_key(kf)
        os.chmod(kf, 0o600)
        self.assertEqual(AppendOnlyLedger.load_key(kf), KEY)

    def test_ed25519_asymmetric_signatures_and_verification(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization

        priv = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        pub_bytes = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        # Append using Ed25519 private key
        ledger = AppendOnlyLedger(self.path, signing_key=priv_bytes, use_ed25519=True)
        ev1 = ledger.append("task.start", "worker", {"task": "deploy"})
        self.assertIsNotNone(ev1.signature)
        self.assertTrue(ev1.signature and ev1.signature.startswith("ed25519:"))

        # Verify directly on the private-key writer ledger (derives public key from seed)
        writer_report = ledger.verify_chain()
        self.assertTrue(writer_report.valid)
        self.assertEqual(writer_report.total_events, 1)

        # Verify with the public key alone
        reader_ledger = AppendOnlyLedger(self.path, verify_key=pub_bytes)
        report = reader_ledger.verify_chain()
        self.assertTrue(report.valid)
        self.assertEqual(report.total_events, 1)

        # Full chain rewrite without private key fails
        _rewrite_chain_without_key(self.path, 1, {"task": "tampered"})
        forged_report = reader_ledger.verify_chain()
        self.assertFalse(forged_report.valid)
        self.assertEqual(forged_report.first_broken_sequence, 1)

    def _ed25519_chain(self, n=3):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv = ed25519.Ed25519PrivateKey.generate()
        seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._fill(AppendOnlyLedger(self.path, signing_key=seed, use_ed25519=True), n)
        return public

    def _rewrite_and_sign(self, sign):
        """An attacker who can write the file changes event 2, then recomputes and re-signs every event."""
        with open(self.path, encoding="utf-8") as fh:
            events = [json.loads(line) for line in fh if line.strip()]
        prev = "0" * 64
        for ev in events:
            if ev["sequence"] == 2:
                ev["payload"] = {"i": "forged"}
            ev["prev_hash"] = prev
            ev["event_hash"] = compute_event_hash(ev["sequence"], ev["event_id"], ev["timestamp"], ev["event_type"],
                                                  ev["actor"], prev, ev["payload"], hash_version=ev["hash_version"])
            ev["signature"] = sign(ev["event_hash"])
            prev = ev["event_hash"]
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(ev) + "\n" for ev in events)

    def test_the_public_key_alone_cannot_forge_an_ed25519_ledger(self):
        public = self._ed25519_chain()
        reader = AppendOnlyLedger(self.path, verify_key=public)
        self.assertTrue(reader.verify_chain().valid)
        forgeries = {
            "HMAC keyed with the public key": lambda event_hash: sign_event_hash(event_hash, public),
            "Ed25519 with the public key's bytes as the seed": lambda event_hash: sign_event_hash_ed25519(event_hash, public),
        }
        for name, sign in forgeries.items():
            with self.subTest(name):
                self._rewrite_and_sign(sign)
                report = reader.verify_chain()
                self.assertFalse(report.valid)
                self.assertEqual(report.first_broken_sequence, 1)

    def test_a_verify_key_ledger_cannot_append(self):
        public = self._ed25519_chain(1)
        with self.assertRaises(PermissionError):
            AppendOnlyLedger(self.path, verify_key=public).append("t", "a", {})

    def test_a_public_key_passed_as_signing_key_fails_with_a_hint(self):
        public = self._ed25519_chain(2)
        report = AppendOnlyLedger(self.path, signing_key=public).verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 1)
        self.assertIn("verify_key", report.error_detail or "")

    def test_signing_key_and_verify_key_are_checked(self):
        with self.assertRaises(ValueError):
            AppendOnlyLedger(self.path, signing_key=KEY, verify_key=b"p" * 32)
        with self.assertRaises(ValueError):
            AppendOnlyLedger(self.path, verify_key=b"short")
        AppendOnlyLedger(self.path, verify_key=b"p" * 32, require_signature=True)  # a verify_key satisfies it

    def test_verify_signature_uses_the_callers_scheme(self):
        public = self._ed25519_chain(1)
        event = AppendOnlyLedger(self.path, verify_key=public).head()
        assert event is not None
        self.assertTrue(verify_signature(event, public, scheme="ed25519"))
        self.assertFalse(verify_signature(event, public))  # the default scheme is HMAC
        hmac_event = event.model_copy(update={"signature": sign_event_hash(event.event_hash, KEY)})
        self.assertTrue(verify_signature(hmac_event, KEY))
        self.assertFalse(verify_signature(hmac_event, KEY, scheme="ed25519"))
        with self.assertRaises(ValueError):
            verify_signature(event, public, scheme="rsa")


if __name__ == "__main__":
    unittest.main()
