# SPDX-License-Identifier: Apache-2.0
"""The Typed Rails data model.

A rail is a quadruple ``⟨Type, Predicate, Evidence, Action⟩``:

* **Type** - a :class:`RailType` combining a :class:`RiskType` (safety, privacy, compliance,
  security, cost, quality) with a :class:`CapabilityType` (tool, api, memory, data, message,
  code);
* **Predicate** - a :class:`~typed_rails.predicates.Predicate` that must hold for the
  interaction to proceed;
* **Evidence** - an :class:`EvidenceSpec` naming the evidence the predicate is evaluated
  over (required keys) and what to capture into the audit record;
* **Action** - :class:`ActionSpec` objects describing what happens when the predicate
  fails (``on_fail``) and passes (``on_pass``).

``Allow(agent, action) = 1 iff predicate(evidence) is true`` for every applicable rail;
post-condition rails (``phase: post``) run after the call and can redact or reject results.
"""

from __future__ import annotations

import enum
import fnmatch
import time
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .predicates import Predicate


class RiskType(str, enum.Enum):
    SAFETY = "safety"
    PRIVACY = "privacy"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    COST = "cost"
    QUALITY = "quality"


class CapabilityType(str, enum.Enum):
    TOOL = "tool"
    API = "api"
    MEMORY = "memory"
    DATA = "data"
    MESSAGE = "message"
    CODE = "code"


class Phase(str, enum.Enum):
    PRE = "pre"
    POST = "post"


class PolicyAction(str, enum.Enum):
    ALLOW = "allow"
    LOG = "log"
    REDACT = "redact"
    THROTTLE = "throttle"
    REQUIRE_APPROVAL = "require_approval"
    QUARANTINE = "quarantine"
    DENY = "deny"


SEVERITY: dict[PolicyAction, int] = {
    PolicyAction.ALLOW: 0,
    PolicyAction.LOG: 1,
    PolicyAction.REDACT: 2,
    PolicyAction.THROTTLE: 3,
    PolicyAction.REQUIRE_APPROVAL: 4,
    PolicyAction.QUARANTINE: 5,
    PolicyAction.DENY: 6,
}
PERMISSIVE: frozenset[PolicyAction] = frozenset({PolicyAction.ALLOW, PolicyAction.LOG, PolicyAction.REDACT})


def most_severe(actions: Iterable[PolicyAction]) -> PolicyAction:
    return max(actions, key=lambda a: SEVERITY[a], default=PolicyAction.ALLOW)


@dataclass(frozen=True)
class RailType:
    risk: RiskType
    capability: CapabilityType = CapabilityType.TOOL

    @property
    def label(self) -> str:
        return f"{self.risk.value}/{self.capability.value}"

    def to_dict(self) -> dict[str, str]:
        return {"risk": self.risk.value, "capability": self.capability.value}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RailType:
        return cls(RiskType(d.get("risk", "compliance")), CapabilityType(d.get("capability", "tool")))


@dataclass
class ActionSpec:
    action: PolicyAction = PolicyAction.DENY
    fields: list[str] = field(default_factory=list)
    detect_pii: bool = True
    message: str | None = None
    retry_after_s: float | None = None
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def parse(cls, value: Any, default: PolicyAction = PolicyAction.DENY) -> ActionSpec:
        if value is None:
            return cls(default)
        if isinstance(value, ActionSpec):
            return value
        if isinstance(value, PolicyAction):
            return cls(value)
        if isinstance(value, str):
            return cls(PolicyAction(value.lower()))
        if isinstance(value, Mapping):
            data = dict(value)
            action = PolicyAction(str(data.pop("action", default.value)).lower())
            fields = data.pop("fields", None)
            if isinstance(fields, str):
                fields = [fields]
            return cls(
                action=action,
                fields=list(fields or []),
                detect_pii=bool(data.pop("detect_pii", True)),
                message=data.pop("message", None),
                retry_after_s=data.pop("retry_after_s", None),
                params=data,
            )
        raise ValueError(f"cannot parse action from {value!r}")

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"action": self.action.value}
        if self.fields:
            d["fields"] = list(self.fields)
        if not self.detect_pii:
            d["detect_pii"] = False
        if self.message:
            d["message"] = self.message
        if self.retry_after_s is not None:
            d["retry_after_s"] = self.retry_after_s
        d.update(self.params)
        return d


@dataclass
class EvidenceSpec:
    required: list[str] = field(default_factory=list)
    capture: list[str] = field(default_factory=list)

    @classmethod
    def parse(cls, value: Any) -> EvidenceSpec:
        if value is None:
            return cls()
        if isinstance(value, EvidenceSpec):
            return value
        if isinstance(value, str):
            return cls(required=[value])
        if isinstance(value, (list, tuple)):
            return cls(required=[str(v) for v in value])
        if isinstance(value, Mapping):
            req = value.get("required", [])
            cap = value.get("capture", [])
            return cls(
                required=[str(v) for v in ([req] if isinstance(req, str) else req)],
                capture=[str(v) for v in ([cap] if isinstance(cap, str) else cap)],
            )
        raise ValueError(f"cannot parse evidence spec from {value!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"required": list(self.required), "capture": list(self.capture)}


@dataclass
class Selector:
    tools: list[str] = field(default_factory=lambda: ["*"])
    agents: list[str] = field(default_factory=lambda: ["*"])
    phases: list[Phase] = field(default_factory=lambda: [Phase.PRE])

    def matches(self, tool: str, agent: str, phase: Phase) -> bool:
        return (
            phase in self.phases
            and any(fnmatch.fnmatchcase(tool, pat) for pat in self.tools)
            and any(fnmatch.fnmatchcase(agent, pat) for pat in self.agents)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": list(self.tools),
            "agents": list(self.agents),
            "phases": [p.value for p in self.phases],
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Selector:
        return cls(
            tools=list(d.get("tools") or ["*"]),
            agents=list(d.get("agents") or ["*"]),
            phases=[Phase(p) for p in (d.get("phases") or ["pre"])],
        )


@dataclass
class Rail:
    id: str
    type: RailType
    predicate: Predicate
    selector: Selector = field(default_factory=Selector)
    evidence: EvidenceSpec = field(default_factory=EvidenceSpec)
    on_fail: ActionSpec = field(default_factory=lambda: ActionSpec(PolicyAction.DENY))
    on_pass: ActionSpec = field(default_factory=lambda: ActionSpec(PolicyAction.ALLOW))
    title: str | None = None
    description: str | None = None
    citation: str | None = None
    tags: list[str] = field(default_factory=list)
    template: str | None = None
    priority: int = 0

    def applies(self, tool: str, agent: str, phase: Phase) -> bool:
        return self.selector.matches(tool, agent, phase)

    @property
    def is_static(self) -> bool:
        """Depends only on the tool name / agent: can be decided before any call is made."""
        return self.predicate.is_static and not self.evidence.required

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.to_dict(),
            "predicate": self.predicate.source,
            "selector": self.selector.to_dict(),
            "evidence": self.evidence.to_dict(),
            "on_fail": self.on_fail.to_dict(),
            "on_pass": self.on_pass.to_dict(),
            "title": self.title,
            "description": self.description,
            "citation": self.citation,
            "tags": list(self.tags),
            "template": self.template,
            "priority": self.priority,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Rail:
        return cls(
            id=str(d["id"]),
            type=RailType.from_dict(d.get("type", {})),
            predicate=Predicate(d["predicate"]),
            selector=Selector.from_dict(d.get("selector", {})),
            evidence=EvidenceSpec.parse(d.get("evidence")),
            on_fail=ActionSpec.parse(d.get("on_fail"), PolicyAction.DENY),
            on_pass=ActionSpec.parse(d.get("on_pass"), PolicyAction.ALLOW),
            title=d.get("title"),
            description=d.get("description"),
            citation=d.get("citation"),
            tags=list(d.get("tags") or []),
            template=d.get("template"),
            priority=int(d.get("priority", 0)),
        )


@dataclass
class CallContext:
    """Everything known about one agent -> tool interaction."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    agent: str = "agent"
    agent_trust: float | None = None
    agent_role: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    session: dict[str, Any] = field(default_factory=dict)
    env: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    phase: Phase = Phase.PRE
    result: Any = None
    call_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    capability: CapabilityType = CapabilityType.TOOL

    def namespace(self, *, trust: float | None = None) -> dict[str, Any]:
        dt = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
        return {
            "tool": self.tool,
            "capability": self.capability.value,
            "args": self.args,
            "agent": {
                "name": self.agent,
                "trust": trust
                if trust is not None
                else (self.agent_trust if self.agent_trust is not None else 1.0),
                "role": self.agent_role,
            },
            "evidence": self.evidence,
            "session": self.session,
            "env": self.env,
            "time": {
                "epoch": self.timestamp,
                "hour": dt.hour,
                "minute": dt.minute,
                "weekday": dt.weekday(),
                "iso": dt.isoformat(),
            },
            "result": self.result,
            "phase": self.phase.value,
            "call_id": self.call_id,
        }

    def with_phase(self, phase: Phase, result: Any = None) -> CallContext:
        return CallContext(
            tool=self.tool,
            args=self.args,
            agent=self.agent,
            agent_trust=self.agent_trust,
            agent_role=self.agent_role,
            evidence=self.evidence,
            session=self.session,
            env=self.env,
            timestamp=self.timestamp,
            phase=phase,
            result=result,
            call_id=self.call_id,
            capability=self.capability,
        )


@dataclass
class RailEvaluation:
    rail_id: str
    type: str
    passed: bool
    action: PolicyAction
    evidence_seen: dict[str, Any] = field(default_factory=dict)
    missing_evidence: list[str] = field(default_factory=list)
    message: str | None = None
    error: str | None = None
    citation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rail_id": self.rail_id,
            "type": self.type,
            "passed": self.passed,
            "action": self.action.value,
            "evidence_seen": self.evidence_seen,
            "missing_evidence": list(self.missing_evidence),
            "message": self.message,
            "error": self.error,
            "citation": self.citation,
        }


@dataclass
class Decision:
    call_id: str
    tool: str
    agent: str
    phase: Phase
    action: PolicyAction
    allowed: bool
    evaluations: list[RailEvaluation] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    args: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    reasons: list[str] = field(default_factory=list)
    approval_required: bool = False
    throttled: bool = False
    retry_after_s: float | None = None
    evaluated_at: float = 0.0
    evaluation_ms: float = 0.0
    evidence_index: int | None = None
    governance: dict[str, Any] | None = None

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def failed_rails(self) -> list[RailEvaluation]:
        return [e for e in self.evaluations if not e.passed]

    def explain(self) -> str:
        head = (
            f"{self.action.value.upper()} {self.agent} -> {self.tool} "
            f"[{self.phase.value}] ({len(self.evaluations)} rail(s))"
        )
        lines = [head]
        for e in self.evaluations:
            status = "pass" if e.passed else "FAIL"
            extra = f" missing evidence: {', '.join(e.missing_evidence)}" if e.missing_evidence else ""
            cite = f" ({e.citation})" if e.citation else ""
            err = f" error: {e.error}" if e.error else ""
            lines.append(f"  - {e.rail_id} [{e.type}] {status} -> {e.action.value}{extra}{cite}{err}")
        if self.redactions:
            lines.append(f"  redacted: {', '.join(self.redactions)}")
        if self.governance:
            lines.append(f"  governance: {self.governance}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "tool": self.tool,
            "agent": self.agent,
            "phase": self.phase.value,
            "action": self.action.value,
            "allowed": self.allowed,
            "evaluations": [e.to_dict() for e in self.evaluations],
            "redactions": list(self.redactions),
            "reasons": list(self.reasons),
            "approval_required": self.approval_required,
            "throttled": self.throttled,
            "retry_after_s": self.retry_after_s,
            "evaluated_at": self.evaluated_at,
            "evaluation_ms": self.evaluation_ms,
            "evidence_index": self.evidence_index,
            "governance": self.governance,
        }


class PolicyDenied(PermissionError):
    """Raised by guards when a call is blocked."""

    def __init__(self, decision: Decision) -> None:
        reason = "; ".join(decision.reasons) or decision.action.value
        super().__init__(f"{decision.tool}: {reason}")
        self.decision = decision


class ApprovalRequired(PolicyDenied):
    pass


class Throttled(PolicyDenied):
    pass
