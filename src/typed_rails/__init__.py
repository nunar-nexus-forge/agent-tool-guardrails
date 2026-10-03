# SPDX-License-Identifier: Apache-2.0
"""Typed Rails (pip install agent-tool-guardrails): typed policy rails for agent-tool calls.

Quick start::

    from typed_rails import CallContext, PolicyEngine, compile_policy

    engine = PolicyEngine(compile_policy("policy.yaml"))

    @engine.guard("transfer_funds", agent="treasury-bot")
    def transfer_funds(amount: float, to: str): ...

    ctx = CallContext(tool="export_report", args={...}, agent="analyst", evidence={"anonymised": True})
    decision = engine.evaluate(ctx)
    print(decision.explain())
    print(engine.evidence.verify())
"""

from __future__ import annotations

from ._version import __version__
from .compiler import TEMPLATES, PolicyCompileError, RailSet, compile_policy, load_policy_document
from .engine import EngineConfig, PolicyEngine
from .evidence import EvidenceRecord, EvidenceStore, VerificationResult, canonical, digest
from .metrics import GovernanceMetrics, compute_metrics, policy_recall
from .model import (
    PERMISSIVE,
    SEVERITY,
    ActionSpec,
    ApprovalRequired,
    CallContext,
    CapabilityType,
    Decision,
    EvidenceSpec,
    Phase,
    PolicyAction,
    PolicyDenied,
    Rail,
    RailEvaluation,
    RailType,
    RiskType,
    Selector,
    Throttled,
    most_severe,
)
from .predicates import Predicate, PredicateError, PredicateSyntaxError
from .redaction import PIIMatch, count_pii, find_pii, redact_text, redact_value, register_pattern
from .sharding import Shard, ShardAccess, ShardAccessDenied, ShardedMemory, ShardPolicy
from .trust import ComplianceTracker, GovernanceConfig, GovernanceLoop, GovernanceState, TrustModel

__all__ = [
    "PERMISSIVE",
    "SEVERITY",
    "TEMPLATES",
    "ActionSpec",
    "ApprovalRequired",
    "CallContext",
    "CapabilityType",
    "ComplianceTracker",
    "Decision",
    "EngineConfig",
    "EvidenceRecord",
    "EvidenceSpec",
    "EvidenceStore",
    "GovernanceConfig",
    "GovernanceLoop",
    "GovernanceMetrics",
    "GovernanceState",
    "PIIMatch",
    "Phase",
    "PolicyAction",
    "PolicyCompileError",
    "PolicyDenied",
    "PolicyEngine",
    "Predicate",
    "PredicateError",
    "PredicateSyntaxError",
    "Rail",
    "RailEvaluation",
    "RailSet",
    "RailType",
    "RiskType",
    "Selector",
    "Shard",
    "ShardAccess",
    "ShardAccessDenied",
    "ShardPolicy",
    "ShardedMemory",
    "Throttled",
    "TrustModel",
    "VerificationResult",
    "__version__",
    "canonical",
    "compile_policy",
    "compute_metrics",
    "count_pii",
    "digest",
    "find_pii",
    "load_policy_document",
    "most_severe",
    "policy_recall",
    "redact_text",
    "redact_value",
    "register_pattern",
]
