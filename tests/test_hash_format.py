"""Hash format 2, signature hardening, anchoring and file-handling regressions for the Python ledger."""

import hashlib
import hmac
import json
import os
import tempfile
import unittest

from argus_ledger import (
    AppendOnlyLedger,
    AuditEvent,
    ChainAnchor,
    CURRENT_HASH_VERSION,
    GENESIS_PREV_HASH,
    SIGNATURE_DOMAIN,
    compute_event_hash,
    compute_payload_digest,
    ed25519_public_key,
    sign_event_hash,
    sign_event_hash_ed25519,
    verify_event,
    verify_signature,
    verify_signature_ed25519,
)

KEY = b"k" * 32
IDENTITY_POINT = bytes.fromhex("01" + "00" * 31)  # small-order Ed25519 point (the neutral element)
FORGED_SIGNATURE = "ed25519:" + (IDENTITY_POINT + bytes(32)).hex()  # R = identity, S = 0


def _records(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _write(path, records):
    with open(path, "w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")


def _legacy_record(sequence, prev_hash, payload, key=None):
    """A record as written before hash_version existed: ':'-joined hash, untagged HMAC."""
    record = {
        "sequence": sequence,
        "event_id": f"legacy-{sequence}",
        "timestamp": f"2026-10-01T00:00:0{sequence}+00:00",
        "event_type": "tool.exec",
        "actor": "agent",
        "payload": payload,
        "prev_hash": prev_hash,
    }
    record["event_hash"] = compute_event_hash(
        sequence, record["event_id"], record["timestamp"], "tool.exec", "agent", prev_hash, payload,
        hash_version=1,
    )
    record["signature"] = sign_event_hash(record["event_hash"], key, hash_version=1) if key else None
    return record


class TestHashFormat(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_v2_matches_the_rust_golden_vectors(self):
        event_id = "ev_0123456789abcdef0123456789abcdef_1"
        actor = "arn:aws:iam::123456789012:user/alice"
        self.assertEqual(
            compute_payload_digest({"command": "build"}),
            "e053d91e793d447a4d3c889162d6303593a89b5c9323850ffcaa6465e5b42345",
        )
        self.assertEqual(
            compute_payload_digest({}), "98db375430d9d7e035552d94f599855e44b9257f5151438a065fa59c583ec93a"
        )
        h1 = compute_event_hash(
            1, event_id, "1760659200000000000", "tool.exec", actor, GENESIS_PREV_HASH, {"command": "build"}
        )
        self.assertEqual(h1, "3a7cfe22bc8ca5b032bca7defaaa1ac22f05c9922dff2bd5032e820f1a927f9b")
        h2 = compute_event_hash(
            (1 << 40) + 1,
            "ev_0123456789abcdef0123456789abcdef_1099511627777",
            "1760659200000000001",
            "policy.override",
            "svc-ci:on-behalf-of:alice",
            h1,
            {},
        )
        self.assertEqual(h2, "27d2430b331e10c1899d323d86bf12ccadc7e8b07772d3941707717cc8a05273")
        seed = bytes([7]) * 32
        self.assertEqual(
            ed25519_public_key(seed).hex(), "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        )
        self.assertEqual(
            sign_event_hash_ed25519(h1, seed),
            "ed25519:73124ea3a9e12a395d4670806d1f1ca21debfa1d1d53949dac5718844ca64748"
            "7b2d6eaf76e8593785308bb522b4a73ced14a206fd2d3327a1b7625a2ba36706",
        )

    def test_field_boundaries_are_bound_into_the_hash(self):
        args = (1, "id", "ts")
        legacy = [
            compute_event_hash(*args, "a:b", "c", GENESIS_PREV_HASH, {}, hash_version=1),
            compute_event_hash(*args, "a", "b:c", GENESIS_PREV_HASH, {}, hash_version=1),
        ]
        self.assertEqual(legacy[0], legacy[1])  # why format 1 is verify-only
        self.assertNotEqual(
            compute_event_hash(*args, "a:b", "c", GENESIS_PREV_HASH, {}),
            compute_event_hash(*args, "a", "b:c", GENESIS_PREV_HASH, {}),
        )

    def test_reattributing_a_record_is_detected_even_when_relabelled_as_format_1(self):
        ledger = AppendOnlyLedger(self.path, signing_key=KEY)
        ledger.append("policy.override:svc-ci", "alice", {"rule": "prod-freeze"})
        for relabel in (False, True):
            records = _records(self.path)
            records[0]["event_type"], records[0]["actor"] = "policy.override", "svc-ci:alice"
            if relabel:
                records[0]["hash_version"] = 1
            _write(self.path, records)
            report = ledger.verify_chain()
            self.assertFalse(report.valid)
            self.assertEqual(report.first_broken_sequence, 1)

    def test_new_events_record_the_current_format(self):
        event = AppendOnlyLedger(self.path).append("tool.exec", "agent", {"x": 1})
        self.assertEqual(event.hash_version, CURRENT_HASH_VERSION)
        self.assertEqual(_records(self.path)[0]["hash_version"], CURRENT_HASH_VERSION)
        self.assertTrue(verify_event(event))

    def test_legacy_ledger_still_verifies_and_continues_in_the_current_format(self):
        records, prev = [], GENESIS_PREV_HASH
        for seq in (1, 2, 3):
            records.append(_legacy_record(seq, prev, {"i": seq}, key=KEY))
            prev = records[-1]["event_hash"]
        _write(self.path, records)
        ledger = AppendOnlyLedger(self.path, signing_key=KEY)
        report = ledger.verify_chain()
        self.assertTrue(report.valid, report.error_detail)
        self.assertEqual(report.legacy_events, 3)

        event = ledger.append("tool.exec", "agent", {"i": 4})
        self.assertEqual((event.sequence, event.prev_hash, event.hash_version), (4, prev, 2))
        report = ledger.verify_chain()
        self.assertTrue(report.valid, report.error_detail)
        self.assertEqual((report.total_events, report.legacy_events), (4, 3))

    def test_format_downgrade_after_a_format_2_record_is_rejected(self):
        ledger = AppendOnlyLedger(self.path)
        first = ledger.append("tool.exec", "agent", {"i": 1})
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(_legacy_record(2, first.event_hash, {"i": 2})) + "\n")
        report = ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 2)
        self.assertIn("downgrade", report.error_detail)

    def test_unknown_hash_format_fails_closed(self):
        AppendOnlyLedger(self.path).append("tool.exec", "agent", {"i": 1})
        records = _records(self.path)
        records[0]["hash_version"] = 3
        _write(self.path, records)
        self.assertFalse(AppendOnlyLedger(self.path).verify_chain().valid)


class TestAnchoringAndReporting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")
        self.ledger = AppendOnlyLedger(self.path)
        self.events = [self.ledger.append("tool.exec", "agent", {"i": i}) for i in range(1, 6)]

    def tearDown(self):
        self.tmp.cleanup()

    def test_anchor_detects_rollback_truncation_and_recomputed_history(self):
        anchor = self.events[-1].anchor()
        self.assertEqual(anchor, ChainAnchor(sequence=5, event_hash=self.events[-1].event_hash))
        report = self.ledger.verify_chain(anchor=anchor)
        self.assertTrue(report.valid and report.anchored)

        records = _records(self.path)
        _write(self.path, records[:3])  # truncation / rollback: internally consistent
        self.assertTrue(self.ledger.verify_chain().valid)
        report = self.ledger.verify_chain(anchor=anchor)
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 5)

        prev = GENESIS_PREV_HASH  # recompute the whole chain with a forged payload
        for record in records:
            if record["sequence"] == 2:
                record["payload"] = {"i": "forged"}
            record["prev_hash"] = prev
            record["event_hash"] = compute_event_hash(
                record["sequence"], record["event_id"], record["timestamp"], record["event_type"],
                record["actor"], prev, record["payload"],
            )
            prev = record["event_hash"]
        _write(self.path, records)
        self.assertTrue(self.ledger.verify_chain().valid)
        self.assertFalse(self.ledger.verify_chain(anchor=anchor).valid)

        _write(self.path, [])  # an emptied ledger cannot satisfy an anchor
        self.assertFalse(self.ledger.verify_chain(anchor=anchor).valid)
        os.remove(self.path)
        self.assertFalse(self.ledger.verify_chain(anchor=anchor).valid)

    def test_first_broken_sequence_is_the_chain_position_not_the_recorded_value(self):
        records = _records(self.path)
        records[1]["sequence"] = 999
        _write(self.path, records)
        report = self.ledger.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 2)

    def test_corrupt_signature_text_fails_closed_instead_of_raising(self):
        keyed_path = os.path.join(self.tmp.name, "keyed.jsonl")
        keyed = AppendOnlyLedger(keyed_path, signing_key=KEY)
        keyed.append("tool.exec", "agent", {"i": 1})
        records = _records(keyed_path)
        records[0]["signature"] = "\u00e9" * 64
        _write(keyed_path, records)
        report = keyed.verify_chain()
        self.assertFalse(report.valid)
        self.assertEqual(report.first_broken_sequence, 1)


class TestSignatureHardening(unittest.TestCase):
    def _event(self, signature, hash_version=2):
        return AuditEvent(
            sequence=1, event_id="e", timestamp="t", event_type="tool.exec", actor="agent",
            prev_hash=GENESIS_PREV_HASH, event_hash="ab" * 32, signature=signature, hash_version=hash_version,
        )

    def test_small_order_public_key_cannot_verify_a_forged_signature(self):
        forged = self._event(FORGED_SIGNATURE)
        self.assertFalse(verify_signature_ed25519(forged, IDENTITY_POINT))
        # The same bytes configured as an HMAC key must not open the Ed25519 path to forgery either.
        self.assertFalse(verify_signature(forged, IDENTITY_POINT))

    def test_hmac_ledger_with_a_point_shaped_key_rejects_forged_ed25519_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audit.jsonl")
            ledger = AppendOnlyLedger(path, signing_key=IDENTITY_POINT)
            ledger.append("tool.exec", "agent", {"i": 1})
            records = _records(path)
            records[0]["payload"] = {"i": "forged"}
            records[0]["event_hash"] = compute_event_hash(
                1, records[0]["event_id"], records[0]["timestamp"], "tool.exec", "agent",
                GENESIS_PREV_HASH, records[0]["payload"],
            )
            records[0]["signature"] = FORGED_SIGNATURE
            _write(path, records)
            self.assertFalse(ledger.verify_chain().valid)

    def test_only_the_canonical_signature_encoding_verifies(self):
        seed = bytes([7]) * 32
        public = ed25519_public_key(seed)
        signature = sign_event_hash_ed25519("ab" * 32, seed)
        self.assertTrue(verify_signature_ed25519(self._event(signature), public))
        encoded = signature[len("ed25519:"):]
        for variant in (
            "ed25519:" + encoded.upper(),
            "ed25519:" + " ".join(encoded[i:i + 2] for i in range(0, len(encoded), 2)),
            "ed25519:" + encoded + "\n",
            "ED25519:" + encoded,
        ):
            self.assertFalse(verify_signature_ed25519(self._event(variant), public), variant)

    def test_signatures_are_domain_separated_from_format_2_on(self):
        seed = bytes([7]) * 32
        public = ed25519_public_key(seed)
        untagged = sign_event_hash_ed25519("ab" * 32, seed, hash_version=1)
        self.assertFalse(verify_signature_ed25519(self._event(untagged), public))
        self.assertTrue(verify_signature_ed25519(self._event(untagged, hash_version=1), public))

        tagged_mac = hmac.new(KEY, SIGNATURE_DOMAIN + ("ab" * 32).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(sign_event_hash("ab" * 32, KEY), tagged_mac)
        self.assertTrue(verify_signature(self._event(tagged_mac), KEY))
        self.assertFalse(verify_signature(self._event(sign_event_hash("ab" * 32, KEY, hash_version=1)), KEY))


class TestTailHandling(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "audit.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def test_head_and_append_read_the_tail_across_block_boundaries(self):
        ledger = AppendOnlyLedger(self.path)
        ledger.append("tool.exec", "agent", {"i": 1})
        big = ledger.append("tool.exec", "agent", {"blob": "x" * 200_000})
        self.assertEqual(ledger.head(), big)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write("\n  \n")  # trailing blank lines are not records
        self.assertEqual(ledger.head(), big)
        nxt = ledger.append("tool.exec", "agent", {"i": 3})
        self.assertEqual((nxt.sequence, nxt.prev_hash), (3, big.event_hash))
        self.assertEqual(list(ledger.iter_events())[-1], nxt)
        self.assertTrue(ledger.verify_chain().valid)

    def test_append_after_a_record_missing_its_newline_keeps_records_separate(self):
        ledger = AppendOnlyLedger(self.path)
        ledger.append("tool.exec", "agent", {"i": 1})
        with open(self.path, "rb+") as fh:
            fh.seek(-1, os.SEEK_END)
            fh.truncate()  # lose the trailing newline
        ledger.append("tool.exec", "agent", {"i": 2})
        report = ledger.verify_chain()
        self.assertTrue(report.valid, report.error_detail)
        self.assertEqual(report.total_events, 2)


if __name__ == "__main__":
    unittest.main()
