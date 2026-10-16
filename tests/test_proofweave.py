"""Unit tests for Argus ProofWeave contemporaneous policy-action-evidence binding."""

import json
import tempfile
import unittest
from argus_ledger import AppendOnlyLedger, PolicyActionBinding


class TestProofWeaveBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".jsonl")
        self.ledger = AppendOnlyLedger(self.tmp.name)

    def tearDown(self):
        self.tmp.close()

    def test_proofweave_binding_creation_allow(self):
        intent = {"action": "deploy_worker", "target": "edge_cluster_1"}
        policy = {"require_auth": True, "allowed_sinks": ["edge_cluster_1"]}
        evidence = {"caller_cert_valid": True, "auth_score": 0.98}

        binding = PolicyActionBinding.create(
            intent=intent,
            policy=policy,
            verdict="ALLOW",
            evidence=evidence,
        )

        self.assertEqual(binding.control_verdict, "ALLOW")
        self.assertTrue(len(binding.intent_digest) == 64)
        self.assertTrue(len(binding.policy_snapshot_hash) == 64)
        self.assertIsNotNone(binding.redemption_token)

        # Append to Argus ledger
        event = self.ledger.append(
            event_type="policy.enforcement",
            actor="gatekeeper",
            payload=binding.to_payload_dict(),
        )

        self.assertEqual(event.sequence, 1)
        self.assertIn("proofweave", event.payload)

        # Verify entire chain remains 100% valid
        report = self.ledger.verify_chain()
        self.assertTrue(report.valid)
        self.assertEqual(report.total_events, 1)

    def test_proofweave_binding_creation_deny(self):
        intent = {"action": "exfiltrate_secret", "target": "unapproved_sink"}
        policy = {"require_auth": True, "allowed_sinks": ["edge_cluster_1"]}

        binding = PolicyActionBinding.create(
            intent=intent,
            policy=policy,
            verdict="DENY",
        )

        self.assertEqual(binding.control_verdict, "DENY")
        self.assertIsNone(binding.redemption_token)


if __name__ == "__main__":
    unittest.main()
