"""F6/F7: the Python writer applies the Rust writer's identifier grammar and integer bound."""
import os
import tempfile
import unittest

from argus_ledger import (
    AppendOnlyLedger,
    FloatPayloadError,
    IdentifierError,
    IntegerRangeError,
    PayloadError,
    reject_float_payload,
    validate_identifiers,
    validate_payload,
)
from argus_ledger.canonical import MAX_IDENTIFIER_BYTES, MAX_SAFE_INTEGER


class IdentifierGrammarTest(unittest.TestCase):
    def test_accepted_forms(self):
        for event_type, actor in [
            ("tool.exec", "agent"),
            ("a", "x"),
            ("agent_startup.v2-beta.0", "arn:aws:iam::123456789012:user/alice"),
            ("x" * MAX_IDENTIFIER_BYTES, "!" * MAX_IDENTIFIER_BYTES),
            ("t.e", "".join(chr(b) for b in range(0x21, 0x7F) if chr(b) not in '"\\')),
        ]:
            with self.subTest(event_type=event_type, actor=actor):
                validate_identifiers(event_type, actor)

    def test_rejected_event_types(self):
        for event_type in ["", "Tool.exec", "tool..exec", ".tool", "tool.", "tool exec", "tool:exec",
                           "tool/exec", "t\u00f6ol", "x" * (MAX_IDENTIFIER_BYTES + 1), None, 3]:
            with self.subTest(event_type=event_type):
                with self.assertRaises(IdentifierError):
                    validate_identifiers(event_type, "agent")

    def test_rejected_actors(self):
        for actor in ["", " ", "a b", "a\tb", "a\nb", 'a"b', "a\\b", '"', "\\", "\u00e9", "a\x7fb",
                      "!" * (MAX_IDENTIFIER_BYTES + 1), None, 3]:
            with self.subTest(actor=actor):
                with self.assertRaises(IdentifierError):
                    validate_identifiers("tool.exec", actor)

    def test_every_byte_the_grammar_accepts_matches_the_rust_rule(self):
        # Rust: event_type bytes [a-z0-9_-] plus '.' as separator; actor bytes 0x21..=0x7e
        # minus '"' and '\\'. 92 actor bytes; 26 + 10 + "_-." = 39 event_type bytes.
        accepted_actor = [b for b in range(0x80) if _ok(lambda: validate_identifiers("t.e", f"x{chr(b)}y"))]
        accepted_type = [b for b in range(0x80) if _ok(lambda: validate_identifiers(f"a{chr(b)}b", "w"))]
        self.assertEqual(len(accepted_actor), 92)
        self.assertEqual(len(accepted_type), 39)
        self.assertNotIn(ord('"'), accepted_actor)
        self.assertNotIn(ord("\\"), accepted_actor)
        self.assertIn(ord("."), accepted_type)


def _ok(fn):
    try:
        fn()
        return True
    except IdentifierError:
        return False


class PayloadGateTest(unittest.TestCase):
    def test_integer_bound(self):
        validate_payload({"max": MAX_SAFE_INTEGER, "min": -MAX_SAFE_INTEGER, "n": [0, {"d": 1}]})
        for bad in [MAX_SAFE_INTEGER + 1, -(MAX_SAFE_INTEGER + 1), 2**63, 2**64, -(2**70)]:
            with self.subTest(bad=bad):
                with self.assertRaises(IntegerRangeError):
                    validate_payload({"k": [1, {"n": bad}]})

    def test_floats_still_rejected_and_old_name_is_an_alias(self):
        with self.assertRaises(FloatPayloadError):
            validate_payload({"x": 1.5})
        with self.assertRaises(FloatPayloadError):
            reject_float_payload({"x": [0.1]})
        self.assertIs(reject_float_payload, validate_payload)
        self.assertTrue(issubclass(FloatPayloadError, PayloadError))
        self.assertTrue(issubclass(IntegerRangeError, PayloadError))

    def test_non_object_and_oversized_payloads(self):
        with self.assertRaises(PayloadError):
            validate_payload([1, 2])
        with self.assertRaises(PayloadError):
            validate_payload({"blob": "x" * (1 << 20)})
        validate_payload({"blob": "x" * ((1 << 20) - 32)})

    def test_bools_and_none_are_not_integers(self):
        validate_payload({"t": True, "f": False, "n": None})


class WriterAppliesGatesTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="argus_gates_")
        self.ledger = AppendOnlyLedger(os.path.join(self.dir, "audit.jsonl"))

    def test_append_refuses_before_writing(self):
        with self.assertRaises(IdentifierError):
            self.ledger.append("tool.exec", 'a"b', {})
        with self.assertRaises(IdentifierError):
            self.ledger.append("Tool.Exec", "agent", {})
        with self.assertRaises(IntegerRangeError):
            self.ledger.append("tool.exec", "agent", {"n": 2**53})
        with self.assertRaises(FloatPayloadError):
            self.ledger.append("tool.exec", "agent", {"n": 0.5})
        self.assertEqual(len(self.ledger), 0)
        self.ledger.append("tool.exec", "agent", {"n": 2**53 - 1})
        self.assertTrue(self.ledger.verify_chain().valid)


if __name__ == "__main__":
    unittest.main()
