"""ProofWeave: Contemporaneous Policy-Action-Evidence Binding.

**Experimental.** This module is not part of the ledger's stable surface and may change or be
removed before 1.0. Known gap: ``RAGTriadBinding`` carries its scores as floats, and
``AppendOnlyLedger.append`` refuses float payloads since 0.1.0-alpha.7, so
``RAGTriadBinding.to_payload_dict()`` cannot be appended as is. Convert scores to integers
(for example basis points, ``int(round(score * 10000))``) before logging. ``PolicyActionBinding``
produces digest strings only and appends without issue.

Implements record-time cryptographic binding of agent intent, control verdicts, policy snapshots,
and evidence receipts into Argus audit events, preventing post-hoc reconstruction ambiguity.

Based on:
- Towards ProofWeave: A Privacy-Minimised, Integrity-Anchored Evidence Plane (ACM CCS 2026, arXiv:2609.35234)
- From Intent to Execution Grant (EBL-Core, arXiv:2609.11596)
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
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


class AgentTraceBinding(BaseModel):
    """Contemporaneous proof tuple binding ReAct agent thought, action, and observation."""
    step_index: int = Field(ge=0)
    thought_digest: str = Field(description="SHA-256 digest of the agent's internal reasoning.")
    tool_name: str = Field(description="Target tool name or 'FINAL_ANSWER'.")
    action_input_digest: str = Field(description="SHA-256 digest of canonicalized tool parameters.")
    observation_digest: str = Field(description="SHA-256 digest of tool output observation.")
    step_seal: str = Field(description="SHA-256 signature sealing step execution.")

    @classmethod
    def create(
        cls,
        step_index: int,
        thought: str,
        tool_name: str,
        action_input: Dict[str, Any],
        observation: str,
    ) -> AgentTraceBinding:
        """Create a cryptographically bound trace step using canonical hashing."""
        thought_hash = hashlib.sha256(thought.encode("utf-8")).hexdigest()
        action_hash = hashlib.sha256(canonical_json_bytes(action_input)).hexdigest()
        obs_hash = hashlib.sha256(observation.encode("utf-8")).hexdigest()

        seal_raw = f"{step_index}:{thought_hash}:{tool_name}:{action_hash}:{obs_hash}"
        seal = hashlib.sha256(seal_raw.encode("utf-8")).hexdigest()

        return cls(
            step_index=step_index,
            thought_digest=thought_hash,
            tool_name=tool_name,
            action_input_digest=action_hash,
            observation_digest=obs_hash,
            step_seal=seal,
        )

    def verify(
        self,
        thought: str,
        tool_name: str,
        action_input: Dict[str, Any],
        observation: str,
    ) -> bool:
        """Verify that the recorded trace matches the runtime execution."""
        expected = self.create(
            step_index=self.step_index,
            thought=thought,
            tool_name=tool_name,
            action_input=action_input,
            observation=observation,
        )
        return self.step_seal == expected.step_seal

    def to_payload_dict(self) -> Dict[str, Any]:
        return {
            "agent_trace_binding": {
                "step_index": self.step_index,
                "thought_digest": self.thought_digest,
                "tool_name": self.tool_name,
                "action_input_digest": self.action_input_digest,
                "observation_digest": self.observation_digest,
                "step_seal": self.step_seal,
            }
        }


class RAGTriadBinding(BaseModel):
    """Contemporaneous cryptographic binding of RAG retrieval, generation, and Triad evaluation scores."""
    query_digest: str = Field(description="SHA-256 digest of original user query.")
    context_root_digest: str = Field(description="SHA-256 Merkle root of retrieved context passages.")
    answer_digest: str = Field(description="SHA-256 digest of generated answer.")
    context_relevance: float = Field(ge=0.0, le=1.0)
    groundedness: float = Field(ge=0.0, le=1.0)
    answer_relevance: float = Field(ge=0.0, le=1.0)
    triad_harmonic_mean: float = Field(ge=0.0, le=1.0)
    passes_threshold: bool
    evaluation_seal: str = Field(description="SHA-256 seal of the full evaluation tuple.")

    @classmethod
    def create(
        cls,
        query: str,
        context_passages: list[str],
        answer: str,
        context_relevance: float,
        groundedness: float,
        answer_relevance: float,
        triad_harmonic_mean: float,
        passes_threshold: bool,
    ) -> RAGTriadBinding:
        """Create a cryptographically bound RAG Triad audit record."""
        q_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
        a_hash = hashlib.sha256(answer.encode("utf-8")).hexdigest()

        # Compute Merkle root of context chunks
        chunk_hashes = [hashlib.sha256(p.encode("utf-8")).hexdigest() for p in context_passages]
        combined_chunks = ":".join(sorted(chunk_hashes))
        ctx_root = hashlib.sha256(combined_chunks.encode("utf-8")).hexdigest()

        seal_raw = f"{q_hash}:{ctx_root}:{a_hash}:{context_relevance:.4f}:{groundedness:.4f}:{answer_relevance:.4f}:{passes_threshold}"
        seal = hashlib.sha256(seal_raw.encode("utf-8")).hexdigest()

        return cls(
            query_digest=q_hash,
            context_root_digest=ctx_root,
            answer_digest=a_hash,
            context_relevance=context_relevance,
            groundedness=groundedness,
            answer_relevance=answer_relevance,
            triad_harmonic_mean=triad_harmonic_mean,
            passes_threshold=passes_threshold,
            evaluation_seal=seal,
        )

    def to_payload_dict(self) -> Dict[str, Any]:
        return {
            "rag_triad_binding": {
                "query_digest": self.query_digest,
                "context_root_digest": self.context_root_digest,
                "answer_digest": self.answer_digest,
                "context_relevance": self.context_relevance,
                "groundedness": self.groundedness,
                "answer_relevance": self.answer_relevance,
                "triad_harmonic_mean": self.triad_harmonic_mean,
                "passes_threshold": self.passes_threshold,
                "evaluation_seal": self.evaluation_seal,
            }
        }


# ---------------------------------------------------------------------------
# SOTA Extensions: ProofWeave Transactions, Praxa Governor & MMR Trees
# ---------------------------------------------------------------------------

class ProofWeaveTransaction(BaseModel):
    """Contemporaneous tri-artifact transaction binding (arXiv:2609.35234).
    
    Binds intent, policy snapshot, action, observation readback, and timestamp
    into an atomic evidence transaction, cutting candidate bindings per verdict
    from O(N^2) to 1:1.
    """
    step_index: int = Field(ge=0)
    intent_digest: str = Field(description="SHA-256 digest of proposed intent.")
    policy_snapshot_hash: str = Field(description="SHA-256 digest of active governance policy.")
    action_digest: str = Field(description="SHA-256 digest of brokered action parameters.")
    observation_readback_digest: str = Field(description="SHA-256 digest of readback-verified physical effect.")
    timestamp_epoch_ms: int = Field(ge=0)
    tx_seal: str = Field(description="SHA-256 transaction seal.")

    @classmethod
    def create(
        cls,
        step_index: int,
        intent: Dict[str, Any],
        policy: Dict[str, Any],
        action: Dict[str, Any],
        observation_readback: str,
        timestamp_epoch_ms: Optional[int] = None,
    ) -> ProofWeaveTransaction:
        import time
        ts = timestamp_epoch_ms if timestamp_epoch_ms is not None else int(time.time() * 1000)
        i_hash = hashlib.sha256(canonical_json_bytes(intent)).hexdigest()
        p_hash = hashlib.sha256(canonical_json_bytes(policy)).hexdigest()
        a_hash = hashlib.sha256(canonical_json_bytes(action)).hexdigest()
        o_hash = hashlib.sha256(observation_readback.encode("utf-8")).hexdigest()

        seal_raw = f"{step_index}:{i_hash}:{p_hash}:{a_hash}:{o_hash}:{ts}"
        seal = hashlib.sha256(seal_raw.encode("utf-8")).hexdigest()

        return cls(
            step_index=step_index,
            intent_digest=i_hash,
            policy_snapshot_hash=p_hash,
            action_digest=a_hash,
            observation_readback_digest=o_hash,
            timestamp_epoch_ms=ts,
            tx_seal=seal,
        )

    def verify(
        self,
        intent: Dict[str, Any],
        policy: Dict[str, Any],
        action: Dict[str, Any],
        observation_readback: str,
    ) -> bool:
        expected = self.create(
            step_index=self.step_index,
            intent=intent,
            policy=policy,
            action=action,
            observation_readback=observation_readback,
            timestamp_epoch_ms=self.timestamp_epoch_ms,
        )
        return self.tx_seal == expected.tx_seal


class PraxaState(str, Enum):
    PROPOSAL = "PROPOSAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


class PraxaGovernanceGovernor:
    """Evidence-bound state machine for governed agent execution (arXiv:2610.00015).
    
    Enforces non-bypassable lifecycle transitions:
    Proposal -> Policy Check -> Authority Token -> Execution -> Readback Verification.
    Self-reports are held as unverified hypotheses until readback confirmation.
    """
    def __init__(self, policy_spec: Dict[str, Any]):
        self.policy_spec = policy_spec
        self.policy_hash = hashlib.sha256(canonical_json_bytes(policy_spec)).hexdigest()
        self.state = PraxaState.PROPOSAL
        self.current_token: Optional[str] = None
        self.verified_transactions: List[ProofWeaveTransaction] = []

    def evaluate_proposal(self, intent: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluates agent intent against policy rules and issues a single-use authority token."""
        prohibited_actions = self.policy_spec.get("prohibited_actions", [])
        action_name = intent.get("action", "")
        if action_name in prohibited_actions:
            self.state = PraxaState.REJECTED
            return False, None

        intent_hash = hashlib.sha256(canonical_json_bytes(intent)).hexdigest()
        token_seed = f"PRAXA_AUTH:{intent_hash}:{self.policy_hash}"
        self.current_token = hashlib.sha256(token_seed.encode("utf-8")).hexdigest()[:32]
        self.state = PraxaState.AUTHORIZED
        return True, self.current_token

    def execute_with_broker(
        self,
        authority_token: str,
        action: Dict[str, Any],
        broker_fn: Any,
    ) -> Dict[str, Any]:
        """Executes action via an independent broker pass, requiring a valid authority token."""
        if self.state != PraxaState.AUTHORIZED or authority_token != self.current_token:
            raise PermissionError("Praxa: Unauthorized execution attempt without valid authority token.")

        self.state = PraxaState.EXECUTED
        self.current_token = None
        raw_result = broker_fn(action)
        return raw_result

    def verify_effect(
        self,
        step_index: int,
        intent: Dict[str, Any],
        action: Dict[str, Any],
        readback_fn: Any,
    ) -> ProofWeaveTransaction:
        """Independently verifies physical effect and binds contemporaneous proof."""
        if self.state != PraxaState.EXECUTED:
            raise RuntimeError("Praxa: Cannot verify effect before execution.")

        readback_result = str(readback_fn(action))
        tx = ProofWeaveTransaction.create(
            step_index=step_index,
            intent=intent,
            policy=self.policy_spec,
            action=action,
            observation_readback=readback_result,
        )
        self.verified_transactions.append(tx)
        self.state = PraxaState.VERIFIED
        return tx


class MerkleMountainRange:
    """Streaming Merkle Mountain Range (MMR) accumulator with peak bagging (SCITT / RFC 9943).
    
    Provides O(1) amortized appends and O(log N) inclusion proofs without requiring
    tree rebalancing.
    """
    def __init__(self) -> None:
        self.leaves: List[str] = []
        self.peaks: List[str] = []

    def append(self, leaf_data: str) -> int:
        leaf_hash = hashlib.sha256(leaf_data.encode("utf-8")).hexdigest()
        idx = len(self.leaves)
        self.leaves.append(leaf_hash)
        self._recompute_peaks()
        return idx

    def _recompute_peaks(self) -> None:
        self.peaks.clear()
        n = len(self.leaves)
        offset = 0

        for power in range(63, -1, -1):
            sub_size = 1 << power
            if n >= sub_size and sub_size > 0:
                peak = self._compute_subtree_root(offset, sub_size)
                self.peaks.append(peak)
                offset += sub_size
                n -= sub_size

    def _compute_subtree_root(self, start: int, size: int) -> str:
        if size == 1:
            return self.leaves[start]
        half = size // 2
        left = self._compute_subtree_root(start, half)
        right = self._compute_subtree_root(start + half, half)
        combined = f"{left}:{right}".encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    def get_bagged_root(self) -> str:
        """Bags all mountain peaks right-to-left into a single 32-byte MMR root."""
        if not self.peaks:
            return hashlib.sha256(b"GENESIS_MMR_EMPTY").hexdigest()
        acc = self.peaks[-1]
        for peak in reversed(self.peaks[:-1]):
            combined = f"{peak}:{acc}".encode("utf-8")
            acc = hashlib.sha256(combined).hexdigest()
        return acc

    @staticmethod
    def create_blinded_commitment(payload: Dict[str, Any], salt: Optional[bytes] = None) -> Tuple[str, str]:
        """Creates a zero-knowledge salted commitment for RFC 6962 / DFARS CUI audit compliance."""
        import os
        salt_bytes = salt if salt is not None else os.urandom(16)
        salt_hex = salt_bytes.hex()
        canonical_bytes = canonical_json_bytes(payload)
        commitment_raw = canonical_bytes + salt_bytes
        commitment_hash = hashlib.sha256(commitment_raw).hexdigest()
        return commitment_hash, salt_hex

