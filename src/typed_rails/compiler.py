# SPDX-License-Identifier: Apache-2.0
"""The policy compiler: declarative requirements -> executable rails.

A policy document (YAML or JSON) lists *requirements*. A requirement is either a **raw
rule** with an explicit predicate, or an instance of a **template** that captures a common
regulatory pattern (approval thresholds, PII redaction, rate limits, trust gates, data
residency, ...). Compilation validates everything, resolves defaults, and produces a
:class:`RailSet` whose ``policy_hash`` identifies exactly which rails were enforced.

Example::

    version: 1
    name: finance
    defaults: {on_fail: deny}
    requirements:
      - id: gdpr-anonymised-exports
        type: privacy
        tools: [generate_invoice, export_report]
        predicate: "evidence.anonymised == true"
        evidence: [anonymised]
        on_fail: {action: redact, fields: [args.customer.email, args.customer.name]}
        citation: "GDPR Art. 5(1)(c)"
      - template: approval_threshold
        tool: transfer_funds
        field: args.amount
        threshold: 1000
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .evidence import digest
from .model import (
    ActionSpec,
    CapabilityType,
    EvidenceSpec,
    Phase,
    PolicyAction,
    Rail,
    RailType,
    RiskType,
    Selector,
)
from .predicates import Predicate, PredicateSyntaxError

SCHEMA_VERSION = 1


class PolicyCompileError(ValueError):
    def __init__(self, message: str, location: str | None = None) -> None:
        super().__init__(f"{location}: {message}" if location else message)
        self.location = location


@dataclass
class RailSet:
    name: str
    rails: list[Rail]
    version: int = SCHEMA_VERSION
    description: str | None = None
    policy_hash: str = ""
    source_hash: str | None = None
    compiled_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.policy_hash:
            self.policy_hash = digest([r.to_dict() for r in self.rails])

    def applicable(self, tool: str, agent: str, phase: Phase) -> list[Rail]:
        rails = [r for r in self.rails if r.applies(tool, agent, phase)]
        rails.sort(key=lambda r: (-r.priority, r.id))
        return rails

    def by_id(self, rail_id: str) -> Rail:
        for r in self.rails:
            if r.id == rail_id:
                return r
        raise KeyError(rail_id)

    def tools(self) -> list[str]:
        return sorted({t for r in self.rails for t in r.selector.tools})

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.version,
            "name": self.name,
            "description": self.description,
            "policy_hash": self.policy_hash,
            "source_hash": self.source_hash,
            "compiled_at": self.compiled_at,
            "metadata": self.metadata,
            "rails": [r.to_dict() for r in self.rails],
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RailSet:
        return cls(
            name=str(d.get("name", "policy")),
            rails=[Rail.from_dict(r) for r in d.get("rails", [])],
            version=int(d.get("schema_version", SCHEMA_VERSION)),
            description=d.get("description"),
            policy_hash=str(d.get("policy_hash", "")),
            source_hash=d.get("source_hash"),
            compiled_at=float(d.get("compiled_at", 0.0)),
            metadata=dict(d.get("metadata") or {}),
        )

    def save(self, path: str | Path) -> Path:
        import json

        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> RailSet:
        import json

        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def explain(self) -> str:
        lines = [f"# Policy `{self.name}`", ""]
        if self.description:
            lines += [self.description, ""]
        lines += [f"{len(self.rails)} rail(s), policy hash `{self.policy_hash[:16]}…`", ""]
        lines += [
            "| id | type | applies to | phase | predicate | on fail | citation |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in self.rails:
            applies = f"tools {', '.join(r.selector.tools)}; agents {', '.join(r.selector.agents)}"
            phases = "/".join(p.value for p in r.selector.phases)
            pred = r.predicate.source.replace("|", "\\|")
            lines.append(
                f"| {r.id} | {r.type.label} | {applies} | {phases} | `{pred}` | "
                f"{r.on_fail.action.value} | {r.citation or ''} |"
            )
        return "\n".join(lines)


# --- loading ------------------------------------------------------------------------


def load_policy_document(source: str | Path | Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Return ``(document, source_text)`` from a path, a YAML/JSON string or a mapping."""
    if isinstance(source, Mapping):
        return dict(source), None
    text: str
    if isinstance(source, Path) or (
        isinstance(source, str)
        and "\n" not in source
        and Path(source).suffix in (".yaml", ".yml", ".json")
        and Path(source).exists()
    ):
        text = Path(source).read_text(encoding="utf-8")
    else:
        text = str(source)
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyCompileError(f"cannot parse policy document: {e}") from e
    if not isinstance(doc, dict):
        raise PolicyCompileError("policy document must be a mapping")
    return doc, text


# --- templates --------------------------------------------------------------------------

TemplateFn = Callable[[Mapping[str, Any], "_Defaults", str], Rail]


@dataclass
class _Defaults:
    on_fail: ActionSpec
    on_pass: ActionSpec
    risk: RiskType
    capability: CapabilityType
    agents: list[str]


def _tools(req: Mapping[str, Any], location: str, required: bool = True) -> list[str]:
    tools = req.get("tools", req.get("tool"))
    applies = req.get("applies_to")
    if tools is None and isinstance(applies, Mapping):
        tools = applies.get("tools")
    if tools is None:
        if required:
            raise PolicyCompileError("template requires 'tool' or 'tools'", location)
        return ["*"]
    return [str(tools)] if isinstance(tools, str) else [str(t) for t in tools]


def _agents(req: Mapping[str, Any], defaults: _Defaults) -> list[str]:
    agents = req.get("agents", req.get("agent"))
    applies = req.get("applies_to")
    if agents is None and isinstance(applies, Mapping):
        agents = applies.get("agents")
    if agents is None:
        return list(defaults.agents)
    return [str(agents)] if isinstance(agents, str) else [str(a) for a in agents]


def _quote(value: Any) -> str:
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_quote(v) for v in value) + "]"
    return str(value)


def _common(
    req: Mapping[str, Any],
    defaults: _Defaults,
    location: str,
    *,
    rail_id: str,
    risk: RiskType,
    predicate: str,
    tools: list[str],
    phase: Phase,
    on_fail: ActionSpec,
    evidence: EvidenceSpec | None = None,
    title: str | None = None,
    capability: CapabilityType | None = None,
    template: str | None = None,
) -> Rail:
    try:
        pred = Predicate(predicate)
    except PredicateSyntaxError as e:
        raise PolicyCompileError(f"invalid predicate: {e}", location) from e
    return Rail(
        id=str(req.get("id", rail_id)),
        type=RailType(
            RiskType(req.get("type", req.get("risk", risk.value))),
            capability or CapabilityType(req.get("capability", defaults.capability.value)),
        ),
        predicate=pred,
        selector=Selector(tools=tools, agents=_agents(req, defaults), phases=[phase]),
        evidence=evidence or EvidenceSpec.parse(req.get("evidence")),
        on_fail=ActionSpec.parse(req.get("on_fail"), on_fail.action)
        if req.get("on_fail") is not None
        else on_fail,
        on_pass=ActionSpec.parse(req.get("on_pass"), PolicyAction.ALLOW)
        if req.get("on_pass") is not None
        else defaults.on_pass,
        title=req.get("title", title),
        description=req.get("description"),
        citation=req.get("citation"),
        tags=[str(t) for t in req.get("tags", [])],
        template=template,
        priority=int(req.get("priority", 0)),
    )


def t_allowed_tools(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    return _common(
        req,
        d,
        loc,
        rail_id=f"allowed-tools-{loc}",
        risk=RiskType.SECURITY,
        predicate=f"tool in {_quote(tools)}",
        tools=["*"],
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="tool not in the agent's allow-list"),
        title="Allowed tools",
        template="allowed_tools",
    )


def t_deny_tools(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    return _common(
        req,
        d,
        loc,
        rail_id=f"deny-tools-{loc}",
        risk=RiskType.SAFETY,
        predicate="false",
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="tool is denied by policy"),
        title="Denied tools",
        template="deny_tools",
    )


def t_approval_threshold(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    fld = str(req.get("field", "args.amount"))
    if "threshold" not in req:
        raise PolicyCompileError("approval_threshold requires 'threshold'", loc)
    thr = req["threshold"]
    op = "<=" if req.get("inclusive", True) else "<"
    predicate = f"{fld} == null or {fld} {op} {_quote(thr)}"
    return _common(
        req,
        d,
        loc,
        rail_id=f"approval-threshold-{loc}",
        risk=RiskType.COMPLIANCE,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.REQUIRE_APPROVAL, message=f"{fld} above {thr} needs human approval"),
        title="Approval threshold",
        template="approval_threshold",
    )


def t_rate_limit(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    max_calls = int(req.get("max_calls", 10))
    per = float(req.get("per_seconds", 60))
    predicate = f"rate(tool, {per}) < {max_calls}"
    return _common(
        req,
        d,
        loc,
        rail_id=f"rate-limit-{loc}",
        risk=RiskType.COST,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(
            PolicyAction.THROTTLE, message=f"more than {max_calls} calls per {per:g}s", retry_after_s=per
        ),
        title="Rate limit",
        template="rate_limit",
    )


def t_trust_gate(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    min_trust = float(req.get("min_trust", 0.7))
    return _common(
        req,
        d,
        loc,
        rail_id=f"trust-gate-{loc}",
        risk=RiskType.SECURITY,
        predicate=f"agent.trust >= {min_trust}",
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message=f"agent trust below {min_trust}"),
        title="Trust gate",
        template="trust_gate",
    )


def t_pii_redaction(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    fields = req.get("fields")
    fields = [fields] if isinstance(fields, str) else list(fields or [])
    kinds = req.get("kinds")
    target = "args" if not fields else fields[0].split(".")[0]
    predicate = (
        f"count_pii({target}) == 0" if not fields else " and ".join(f"count_pii({f}) == 0" for f in fields)
    )
    return _common(
        req,
        d,
        loc,
        rail_id=f"pii-redaction-{loc}",
        risk=RiskType.PRIVACY,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(
            PolicyAction.REDACT,
            fields=fields,
            message="personal data redacted before the call",
            params={"kinds": kinds} if kinds else {},
        ),
        title="PII redaction",
        template="pii_redaction",
    )


def t_output_pii_redaction(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    return _common(
        req,
        d,
        loc,
        rail_id=f"output-pii-redaction-{loc}",
        risk=RiskType.PRIVACY,
        predicate="count_pii(result) == 0",
        tools=tools,
        phase=Phase.POST,
        on_fail=ActionSpec(PolicyAction.REDACT, fields=[], message="personal data redacted from the result"),
        title="Output PII redaction",
        template="output_pii_redaction",
    )


def t_time_window(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    start, end = (req.get("hours") or [8, 18])[:2]
    days = req.get("weekdays")
    predicate = f"time.hour >= {int(start)} and time.hour < {int(end)}"
    if days:
        predicate += f" and time.weekday in {_quote([int(x) for x in days])}"
    return _common(
        req,
        d,
        loc,
        rail_id=f"time-window-{loc}",
        risk=RiskType.COMPLIANCE,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="outside the permitted time window (UTC)"),
        title="Time window",
        template="time_window",
    )


def t_data_residency(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    regions = req.get("allowed_regions") or req.get("regions")
    if not regions:
        raise PolicyCompileError("data_residency requires 'allowed_regions'", loc)
    fld = str(req.get("field", "evidence.region"))
    return _common(
        req,
        d,
        loc,
        rail_id=f"data-residency-{loc}",
        risk=RiskType.COMPLIANCE,
        predicate=f"{fld} in {_quote(list(regions))}",
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="data must stay within the allowed regions"),
        evidence=EvidenceSpec(required=[fld.split(".", 1)[1]] if fld.startswith("evidence.") else []),
        title="Data residency",
        template="data_residency",
    )


def t_purpose_limitation(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    purposes = req.get("allowed_purposes") or req.get("purposes")
    if not purposes:
        raise PolicyCompileError("purpose_limitation requires 'allowed_purposes'", loc)
    fld = str(req.get("field", "evidence.purpose"))
    return _common(
        req,
        d,
        loc,
        rail_id=f"purpose-limitation-{loc}",
        risk=RiskType.PRIVACY,
        predicate=f"{fld} in {_quote(list(purposes))}",
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="processing purpose not permitted"),
        evidence=EvidenceSpec(required=[fld.split(".", 1)[1]] if fld.startswith("evidence.") else []),
        title="Purpose limitation",
        template="purpose_limitation",
    )


def t_sandbox_required(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc)
    fld = str(req.get("field", "evidence.sandbox"))
    return _common(
        req,
        d,
        loc,
        rail_id=f"sandbox-required-{loc}",
        risk=RiskType.SAFETY,
        predicate=f"{fld} == true",
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="code execution requires a sandbox"),
        evidence=EvidenceSpec(required=[fld.split(".", 1)[1]] if fld.startswith("evidence.") else []),
        title="Sandbox required",
        capability=CapabilityType.CODE,
        template="sandbox_required",
    )


def t_max_output_size(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    max_chars = int(req.get("max_chars", 10000))
    return _common(
        req,
        d,
        loc,
        rail_id=f"max-output-size-{loc}",
        risk=RiskType.COST,
        predicate=f"len(str(result)) <= {max_chars}",
        tools=tools,
        phase=Phase.POST,
        on_fail=ActionSpec(PolicyAction.DENY, message=f"result larger than {max_chars} characters"),
        title="Maximum output size",
        template="max_output_size",
    )


def t_evidence_required(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    keys = req.get("keys") or req.get("evidence")
    if not keys:
        raise PolicyCompileError("evidence_required requires 'keys'", loc)
    keys = [keys] if isinstance(keys, str) else [str(k) for k in keys]
    predicate = " and ".join(f"exists(evidence.{k})" for k in keys)
    return _common(
        req,
        d,
        loc,
        rail_id=f"evidence-required-{loc}",
        risk=RiskType.COMPLIANCE,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message=f"missing evidence: {', '.join(keys)}"),
        evidence=EvidenceSpec(required=keys),
        title="Evidence required",
        template="evidence_required",
    )


def t_forbidden_patterns(req: Mapping[str, Any], d: _Defaults, loc: str) -> Rail:
    tools = _tools(req, loc, required=False)
    patterns = req.get("patterns")
    if not patterns:
        raise PolicyCompileError("forbidden_patterns requires 'patterns'", loc)
    patterns = [patterns] if isinstance(patterns, str) else [str(p) for p in patterns]
    target = str(req.get("field", "args"))
    predicate = " and ".join(f"not matches({target}, {_quote(p)})" for p in patterns)
    return _common(
        req,
        d,
        loc,
        rail_id=f"forbidden-patterns-{loc}",
        risk=RiskType.SAFETY,
        predicate=predicate,
        tools=tools,
        phase=Phase.PRE,
        on_fail=ActionSpec(PolicyAction.DENY, message="arguments match a forbidden pattern"),
        title="Forbidden patterns",
        template="forbidden_patterns",
    )


TEMPLATES: dict[str, TemplateFn] = {
    "allowed_tools": t_allowed_tools,
    "deny_tools": t_deny_tools,
    "approval_threshold": t_approval_threshold,
    "rate_limit": t_rate_limit,
    "trust_gate": t_trust_gate,
    "pii_redaction": t_pii_redaction,
    "output_pii_redaction": t_output_pii_redaction,
    "time_window": t_time_window,
    "data_residency": t_data_residency,
    "purpose_limitation": t_purpose_limitation,
    "sandbox_required": t_sandbox_required,
    "max_output_size": t_max_output_size,
    "evidence_required": t_evidence_required,
    "forbidden_patterns": t_forbidden_patterns,
}

_RAW_KEYS = {
    "id",
    "title",
    "description",
    "type",
    "risk",
    "capability",
    "tools",
    "tool",
    "agents",
    "agent",
    "applies_to",
    "phase",
    "predicate",
    "evidence",
    "capture",
    "on_fail",
    "on_pass",
    "citation",
    "tags",
    "priority",
}
_TEMPLATE_COMMON_KEYS = _RAW_KEYS | {
    "template",
    "field",
    "threshold",
    "inclusive",
    "max_calls",
    "per_seconds",
    "min_trust",
    "fields",
    "kinds",
    "hours",
    "weekdays",
    "allowed_regions",
    "regions",
    "allowed_purposes",
    "purposes",
    "max_chars",
    "keys",
    "patterns",
}


def compile_requirement(req: Mapping[str, Any], defaults: _Defaults, index: int) -> Rail:
    loc = str(req.get("id") or f"requirements[{index}]")
    if not isinstance(req, Mapping):
        raise PolicyCompileError("requirement must be a mapping", loc)
    template = req.get("template")
    if template is not None:
        fn = TEMPLATES.get(str(template))
        if fn is None:
            raise PolicyCompileError(
                f"unknown template {template!r}; available: {', '.join(sorted(TEMPLATES))}", loc
            )
        unknown = set(req) - _TEMPLATE_COMMON_KEYS
        if unknown:
            raise PolicyCompileError(f"unknown keys {sorted(unknown)}", loc)
        rail = fn(req, defaults, str(index))
        if req.get("phase"):
            rail.selector.phases = _phases(req["phase"], loc)
        return rail
    unknown = set(req) - _RAW_KEYS
    if unknown:
        raise PolicyCompileError(f"unknown keys {sorted(unknown)}", loc)
    if "predicate" not in req:
        raise PolicyCompileError("requirement needs a 'predicate' or a 'template'", loc)
    try:
        risk = RiskType(str(req.get("type", req.get("risk", defaults.risk.value))))
    except ValueError as e:
        raise PolicyCompileError(
            f"unknown risk type {req.get('type')!r}; choose from {', '.join(r.value for r in RiskType)}", loc
        ) from e
    try:
        capability = CapabilityType(str(req.get("capability", defaults.capability.value)))
    except ValueError as e:
        raise PolicyCompileError(f"unknown capability {req.get('capability')!r}", loc) from e
    try:
        predicate = Predicate(str(req["predicate"]))
    except PredicateSyntaxError as e:
        raise PolicyCompileError(f"invalid predicate: {e}", loc) from e
    try:
        on_fail = (
            ActionSpec.parse(req.get("on_fail"), defaults.on_fail.action)
            if req.get("on_fail") is not None
            else defaults.on_fail
        )
        on_pass = (
            ActionSpec.parse(req.get("on_pass"), PolicyAction.ALLOW)
            if req.get("on_pass") is not None
            else defaults.on_pass
        )
    except ValueError as e:
        raise PolicyCompileError(f"invalid action: {e}", loc) from e
    evidence = EvidenceSpec.parse(req.get("evidence"))
    if req.get("capture"):
        cap = req["capture"]
        evidence.capture.extend([cap] if isinstance(cap, str) else [str(c) for c in cap])
    return Rail(
        id=str(req.get("id") or f"rule-{index}"),
        type=RailType(risk, capability),
        predicate=predicate,
        selector=Selector(
            tools=_tools(req, loc, required=False),
            agents=_agents(req, defaults),
            phases=_phases(req.get("phase", "pre"), loc),
        ),
        evidence=evidence,
        on_fail=on_fail,
        on_pass=on_pass,
        title=req.get("title"),
        description=req.get("description"),
        citation=req.get("citation"),
        tags=[str(t) for t in req.get("tags", [])],
        priority=int(req.get("priority", 0)),
    )


def _phases(value: Any, loc: str) -> list[Phase]:
    if value in ("both", "all"):
        return [Phase.PRE, Phase.POST]
    values = [value] if isinstance(value, str) else list(value)
    try:
        return [Phase(str(v)) for v in values]
    except ValueError as e:
        raise PolicyCompileError(f"unknown phase {value!r}; use pre, post or both", loc) from e


def compile_policy(source: str | Path | Mapping[str, Any]) -> RailSet:
    doc, text = load_policy_document(source)
    version = int(doc.get("version", SCHEMA_VERSION))
    if version != SCHEMA_VERSION:
        raise PolicyCompileError(
            f"unsupported policy version {version}; this compiler supports {SCHEMA_VERSION}"
        )
    unknown = set(doc) - {"version", "name", "description", "defaults", "requirements", "metadata"}
    if unknown:
        raise PolicyCompileError(f"unknown top-level keys {sorted(unknown)}")
    raw_defaults = doc.get("defaults") or {}
    try:
        defaults = _Defaults(
            on_fail=ActionSpec.parse(raw_defaults.get("on_fail"), PolicyAction.DENY),
            on_pass=ActionSpec.parse(raw_defaults.get("on_pass"), PolicyAction.ALLOW),
            risk=RiskType(str(raw_defaults.get("type", raw_defaults.get("risk", "compliance")))),
            capability=CapabilityType(str(raw_defaults.get("capability", "tool"))),
            agents=[
                str(a)
                for a in (
                    [raw_defaults["agents"]]
                    if isinstance(raw_defaults.get("agents"), str)
                    else raw_defaults.get("agents") or ["*"]
                )
            ],
        )
    except ValueError as e:
        raise PolicyCompileError(f"invalid defaults: {e}", "defaults") from e
    reqs = doc.get("requirements")
    if not isinstance(reqs, list) or not reqs:
        raise PolicyCompileError("'requirements' must be a non-empty list")
    rails = [compile_requirement(r, defaults, i) for i, r in enumerate(reqs)]
    ids = [r.id for r in rails]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise PolicyCompileError(f"duplicate rail ids: {dupes}")
    return RailSet(
        name=str(doc.get("name", "policy")),
        rails=rails,
        description=doc.get("description"),
        source_hash=digest(text) if text is not None else None,
        metadata=dict(doc.get("metadata") or {}),
    )
