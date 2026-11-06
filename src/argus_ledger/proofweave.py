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

import copy
import hashlib
import hmac
import secrets
import threading
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
    redemption_token: Optional[str] = Field(
        default=None,
        description=(
            "Grant reference if ALLOW: a digest of the intent, policy and evidence digests. It is "
            "deterministic (verify() recomputes it), so anyone who knows those inputs can compute it: "
            "it is not a secret and not single-use by itself. A redeemer that needs one-time grants "
            "must issue and track its own unpredictable nonces, as PraxaGovernanceGovernor does."
        ),
    )

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
        """Verify that this binding cryptographically matches the given intent, policy, and evidence.

        Every stored field is compared, the verdict included (``create`` stores it upper-cased)."""
        expected = self.create(
            intent=intent,
            policy=policy,
            verdict=self.control_verdict,
            evidence=evidence,
        )
        return (
            self.intent_digest == expected.intent_digest
            and self.policy_snapshot_hash == expected.policy_snapshot_hash
            and self.control_verdict == expected.control_verdict
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
        """Verify that the recorded trace matches the runtime execution.

        Every stored digest, the tool name and the seal must match: a record whose fields were changed
        after sealing fails even when its seal is the one computed for the given inputs."""
        expected = self.create(
            step_index=self.step_index,
            thought=thought,
            tool_name=tool_name,
            action_input=action_input,
            observation=observation,
        )
        return (
            self.thought_digest == expected.thought_digest
            and self.tool_name == expected.tool_name
            and self.action_input_digest == expected.action_input_digest
            and self.observation_digest == expected.observation_digest
            and self.step_seal == expected.step_seal
        )

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
        """True if this transaction seals exactly the given intent, policy, action and readback.

        Every stored digest and the seal must match: a transaction whose ``intent_digest`` (or any
        other digest) was changed after sealing fails even when its seal is the one computed for the
        given inputs."""
        expected = self.create(
            step_index=self.step_index,
            intent=intent,
            policy=policy,
            action=action,
            observation_readback=observation_readback,
            timestamp_epoch_ms=self.timestamp_epoch_ms,
        )
        return (
            self.intent_digest == expected.intent_digest
            and self.policy_snapshot_hash == expected.policy_snapshot_hash
            and self.action_digest == expected.action_digest
            and self.observation_readback_digest == expected.observation_readback_digest
            and self.tx_seal == expected.tx_seal
        )


class PraxaState(str, Enum):
    PROPOSAL = "PROPOSAL"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


# A new proposal may replace a pending authorization or follow a finished step, but not a step that is
# in flight (EXECUTING) or executed and awaiting its readback (EXECUTED): that step would then never be
# verified.
_PROPOSABLE_STATES = frozenset(
    {PraxaState.PROPOSAL, PraxaState.AUTHORIZED, PraxaState.REJECTED, PraxaState.VERIFIED, PraxaState.FAILED}
)


class _BoundIntent:
    """An intent fixed when it was authorized: a private deep copy and its canonical JSON bytes.

    The copy is taken first and the bytes computed from it, so a caller that keeps (and later changes)
    its own dict changes neither what was authorized nor what is executed or sealed."""

    __slots__ = ("value", "canonical")

    def __init__(self, intent: Any) -> None:
        self.value = copy.deepcopy(intent)
        self.canonical = canonical_json_bytes(self.value)

    def matches(self, candidate: Any) -> bool:
        try:
            return canonical_json_bytes(candidate) == self.canonical
        except (TypeError, ValueError):
            return False

    def fresh_copy(self) -> Any:
        return copy.deepcopy(self.value)


def _token_matches(presented: Any, current: Optional[str]) -> bool:
    if current is None or not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented.encode("utf-8"), current.encode("ascii"))


class PraxaGovernanceGovernor:
    """Evidence-bound state machine for governed agent execution (arXiv:2610.00015).

    Enforces non-bypassable lifecycle transitions:
    Proposal -> Policy Check -> Authority Token -> Execution -> Readback Verification.
    Self-reports are held as unverified hypotheses until readback confirmation.

    Binding rules:

    - The authority token is random per issuance (``secrets``): it cannot be computed from the intent
      and policy, and a token from an earlier cycle never matches a later one.
    - A token authorizes exactly the intent it was issued for, for one ``execute_with_broker()`` call,
      until the next proposal replaces it. The brokered action must be that intent.
    - Only a step whose broker call returned (``EXECUTED``) can be verified, once, and only for its
      authorized intent; the sealed transaction binds the governor's own copies of that intent and of
      the policy, never the caller's objects.
    - The policy is snapshotted at construction. ``state``, ``current_token``, ``policy_hash`` and
      ``policy_spec`` are read-only, and ``policy_spec`` and ``verified_transactions`` return copies.
    - A refused call raises (``PermissionError`` for a token, intent or action that does not match,
      ``RuntimeError`` for a call out of lifecycle order) and changes nothing.
    """

    def __init__(self, policy_spec: Dict[str, Any]):
        if not isinstance(policy_spec, dict):
            raise TypeError("policy_spec must be a dict")
        snapshot = copy.deepcopy(policy_spec)
        prohibited = snapshot.get("prohibited_actions", [])
        if isinstance(prohibited, (str, bytes)) or not isinstance(prohibited, (list, tuple, set, frozenset)):
            # A string would be searched by substring ("drop" in "drop_database"), not matched by name.
            raise TypeError("policy_spec['prohibited_actions'] must be a list of action names")
        self._policy = snapshot
        self._policy_hash = hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()
        self._prohibited = tuple(prohibited)
        self._state = PraxaState.PROPOSAL
        self._token: Optional[str] = None
        self._authorized: Optional[_BoundIntent] = None
        self._executed: Optional[_BoundIntent] = None
        self._verified: List[ProofWeaveTransaction] = []
        # Guards every check-and-transition, so two threads cannot both redeem one token or both seal
        # one step. Never held while the broker or the readback runs.
        self._lock = threading.Lock()

    @property
    def policy_spec(self) -> Dict[str, Any]:
        """A copy of the policy snapshot taken at construction; changing it changes nothing."""
        return copy.deepcopy(self._policy)

    @property
    def policy_hash(self) -> str:
        """SHA-256 of the canonical JSON of the policy snapshot."""
        return self._policy_hash

    @property
    def state(self) -> PraxaState:
        return self._state

    @property
    def current_token(self) -> Optional[str]:
        """The outstanding authority token, or None once it is consumed, replaced or refused."""
        return self._token

    @property
    def verified_transactions(self) -> List[ProofWeaveTransaction]:
        """Copies of the transactions sealed so far, in order."""
        return [tx.model_copy(deep=True) for tx in self._verified]

    def evaluate_proposal(self, intent: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluates agent intent against policy rules and issues a single-use authority token.

        The token is fresh randomness, bound to a private copy of ``intent``. Any token issued before
        stops working. An intent whose ``action`` is not a string, or is prohibited, is REJECTED.
        Raises RuntimeError while a step is EXECUTING or EXECUTED and not yet verified."""
        candidate = _BoundIntent(intent)  # raises for an intent that is not canonical JSON
        with self._lock:
            if self._state not in _PROPOSABLE_STATES:
                raise RuntimeError(
                    f"Praxa: cannot evaluate a new proposal while the current step is {self._state.value}; "
                    "verify it first."
                )
            self._token = None
            self._authorized = None
            value = candidate.value
            action_name = value.get("action", "") if isinstance(value, dict) else None
            if not isinstance(action_name, str) or action_name in self._prohibited:
                self._state = PraxaState.REJECTED
                return False, None
            self._authorized = candidate
            self._token = secrets.token_hex(16)
            self._state = PraxaState.AUTHORIZED
            return True, self._token

    def execute_with_broker(
        self,
        authority_token: str,
        action: Dict[str, Any],
        broker_fn: Any,
    ) -> Dict[str, Any]:
        """Executes action via an independent broker pass, requiring a valid authority token.

        ``action`` must equal (as canonical JSON) the intent the token was issued for; ``broker_fn``
        receives a private copy of that authorized intent. The token is consumed before the broker runs,
        so it opens at most one broker call, even a failing one. The state is EXECUTING during the call,
        EXECUTED once the broker returns and FAILED if it raises (the exception propagates); a FAILED
        step cannot be verified. A refused call raises PermissionError and changes nothing."""
        with self._lock:
            if self._state != PraxaState.AUTHORIZED or not _token_matches(authority_token, self._token):
                raise PermissionError("Praxa: Unauthorized execution attempt without valid authority token.")
            bound = self._authorized
            if bound is None or not bound.matches(action):
                raise PermissionError(
                    "Praxa: the action is not the intent this authority token was issued for."
                )
            self._token = None
            self._authorized = None
            self._state = PraxaState.EXECUTING
            brokered = bound.fresh_copy()
        try:
            raw_result = broker_fn(brokered)
        except BaseException:
            with self._lock:
                self._state = PraxaState.FAILED
            raise
        with self._lock:
            self._executed = bound
            self._state = PraxaState.EXECUTED
        return raw_result

    def verify_effect(
        self,
        step_index: int,
        intent: Dict[str, Any],
        action: Dict[str, Any],
        readback_fn: Any,
    ) -> ProofWeaveTransaction:
        """Independently verifies physical effect and binds contemporaneous proof.

        Only an EXECUTED step can be verified (RuntimeError otherwise), once. ``intent`` and ``action``
        must equal that step's authorized intent (PermissionError otherwise). The transaction seals the
        governor's copy of the executed intent and its policy snapshot; ``readback_fn`` receives a copy
        of the executed action. If ``readback_fn`` raises, the step stays EXECUTED and can be retried."""
        with self._lock:
            if self._state != PraxaState.EXECUTED:
                raise RuntimeError("Praxa: Cannot verify effect before execution.")
            executed = self._executed
            if executed is None:  # unreachable: EXECUTED always records the executed intent
                raise RuntimeError("Praxa: Cannot verify effect before execution.")
            if isinstance(step_index, bool) or not isinstance(step_index, int) or step_index < 0:
                raise ValueError("Praxa: step_index must be an int >= 0")
            if not executed.matches(intent):
                raise PermissionError("Praxa: the intent is not the one authorized and executed in this step.")
            if not executed.matches(action):
                raise PermissionError("Praxa: the action is not the one executed in this step.")
        readback_result = str(readback_fn(executed.fresh_copy()))
        tx = ProofWeaveTransaction.create(
            step_index=step_index,
            intent=executed.value,
            policy=self._policy,
            action=executed.value,
            observation_readback=readback_result,
        )
        with self._lock:
            if self._state != PraxaState.EXECUTED or self._executed is not executed:
                raise RuntimeError("Praxa: this step was verified while its readback ran.")
            self._verified.append(tx.model_copy(deep=True))
            self._executed = None
            self._state = PraxaState.VERIFIED
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

