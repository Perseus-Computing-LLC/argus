"""ProofWeave: Contemporaneous Policy-Action-Evidence Binding.

Implements record-time cryptographic binding of agent intent, control verdicts, policy snapshots,
and evidence receipts into Argus audit events, preventing post-hoc reconstruction ambiguity.

Based on:
- Towards ProofWeave: A Privacy-Minimised, Integrity-Anchored Evidence Plane (ACM CCS 2026, arXiv:2609.35234)
- From Intent to Execution Grant (EBL-Core, arXiv:2609.11596)
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from .canonical import canonical_json_bytes


class PolicyActionBinding(BaseModel):
    """Contemporaneous proof tuple binding intent, control, and policy."""
    intent_digest: str = Field(description="SHA-256 digest of canonicalized candidate intent.")
    policy_snapshot_hash: str = Field(description="SHA-256 digest of the operational policy in force.")
    control_verdict: str = Field(description="Authorization verdict (e.g. ALLOW, DENY, REDIRECT).")
    evidence_receipt_hash: str = Field(default="", description="SHA-256 digest of the verified precondition evidence.")
    redemption_token: Optional[str] = Field(default=None, description="One-time grant token if ALLOW.")

    @classmethod
    def create(
        cls,
        intent: Dict[str, Any],
        policy: Dict[str, Any],
        verdict: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> PolicyActionBinding:
        """Create a cryptographically bound policy-action record using canonical JSON serialization."""
        intent_hash = hashlib.sha256(canonical_json_bytes(intent)).hexdigest()
        policy_hash = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()
        evidence_hash = hashlib.sha256(canonical_json_bytes(evidence or {})).hexdigest()

        token = None
        if verdict.upper() == "ALLOW":
            raw_token = f"{intent_hash}:{policy_hash}:{evidence_hash}"
            token = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()[:32]

        return cls(
            intent_digest=intent_hash,
            policy_snapshot_hash=policy_hash,
            control_verdict=verdict.upper(),
            evidence_receipt_hash=evidence_hash,
            redemption_token=token,
        )

    def verify(
        self,
        intent: Dict[str, Any],
        policy: Dict[str, Any],
        evidence: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Verify that this binding cryptographically matches the given intent, policy, and evidence."""
        expected = self.create(
            intent=intent,
            policy=policy,
            verdict=self.control_verdict,
            evidence=evidence,
        )
        return (
            self.intent_digest == expected.intent_digest
            and self.policy_snapshot_hash == expected.policy_snapshot_hash
            and self.evidence_receipt_hash == expected.evidence_receipt_hash
            and self.redemption_token == expected.redemption_token
        )

    def to_payload_dict(self) -> Dict[str, Any]:
        """Convert binding to structured dictionary for Argus event payload."""
        return {
            "proofweave": {
                "intent_digest": self.intent_digest,
                "policy_snapshot_hash": self.policy_snapshot_hash,
                "control_verdict": self.control_verdict,
                "evidence_receipt_hash": self.evidence_receipt_hash,
                "redemption_token": self.redemption_token,
            }
        }
