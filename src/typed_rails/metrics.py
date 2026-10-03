# SPDX-License-Identifier: Apache-2.0
"""Governance metrics derived from the Evidence Store."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from .evidence import EvidenceRecord
from .model import PERMISSIVE, PolicyAction


@dataclass
class GovernanceMetrics:
    decisions: int
    allowed: int
    blocked: int
    coverage: float
    safety_incident_rate: float
    redaction_rate: float
    approval_rate: float
    throttle_rate: float
    time_to_first_block_s: float | None
    mean_evaluation_ms: float | None
    by_action: dict[str, int] = field(default_factory=dict)
    by_rail: dict[str, dict[str, int]] = field(default_factory=dict)
    by_agent: dict[str, dict[str, int]] = field(default_factory=dict)
    approvals_granted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        rows = [
            ("decisions", str(self.decisions)),
            ("allowed / blocked", f"{self.allowed} / {self.blocked}"),
            ("coverage (calls with an applicable rail)", _pct(self.coverage)),
            ("safety incident rate (blocked / decisions)", _pct(self.safety_incident_rate)),
            ("redaction rate", _pct(self.redaction_rate)),
            ("approval-required rate", _pct(self.approval_rate)),
            ("throttle rate", _pct(self.throttle_rate)),
            (
                "time to first block",
                "n/a" if self.time_to_first_block_s is None else f"{self.time_to_first_block_s:.1f}s",
            ),
            (
                "mean evaluation time",
                "n/a" if self.mean_evaluation_ms is None else f"{self.mean_evaluation_ms:.3f} ms",
            ),
        ]
        out = ["| metric | value |", "|---|---|"] + [f"| {k} | {v} |" for k, v in rows]
        if self.by_rail:
            out += ["", "| rail | evaluations | failed |", "|---|---|---|"]
            out += [f"| {r} | {v['evaluations']} | {v['failed']} |" for r, v in sorted(self.by_rail.items())]
        if self.by_agent:
            out += ["", "| agent | decisions | blocked |", "|---|---|---|"]
            out += [f"| {a} | {v['decisions']} | {v['blocked']} |" for a, v in sorted(self.by_agent.items())]
        return "\n".join(out)


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"


def compute_metrics(records: Iterable[EvidenceRecord]) -> GovernanceMetrics:
    decisions = [r for r in records if r.kind == "decision"]
    approvals = sum(1 for r in records if r.kind == "approval")
    n = len(decisions)
    by_action: Counter[str] = Counter(r.action or "allow" for r in decisions)
    blocked = sum(1 for r in decisions if r.action and PolicyAction(r.action) not in PERMISSIVE)
    covered = sum(1 for r in decisions if r.rails)
    redacted = sum(1 for r in decisions if r.redactions)
    approvals_required = by_action.get(PolicyAction.REQUIRE_APPROVAL.value, 0)
    throttled = by_action.get(PolicyAction.THROTTLE.value, 0)
    first_t = decisions[0].t if decisions else None
    first_block = next(
        (r.t for r in decisions if r.action and PolicyAction(r.action) not in PERMISSIVE), None
    )
    eval_ms = [float(r.payload["evaluation_ms"]) for r in decisions if "evaluation_ms" in r.payload]
    by_rail: dict[str, dict[str, int]] = defaultdict(lambda: {"evaluations": 0, "failed": 0})
    by_agent: dict[str, dict[str, int]] = defaultdict(lambda: {"decisions": 0, "blocked": 0})
    for r in decisions:
        for ev in r.rails:
            rid = str(ev.get("rail_id"))
            by_rail[rid]["evaluations"] += 1
            if not ev.get("passed", True):
                by_rail[rid]["failed"] += 1
        agent = r.agent or "?"
        by_agent[agent]["decisions"] += 1
        if r.action and PolicyAction(r.action) not in PERMISSIVE:
            by_agent[agent]["blocked"] += 1
    return GovernanceMetrics(
        decisions=n,
        allowed=n - blocked,
        blocked=blocked,
        coverage=(covered / n) if n else 0.0,
        safety_incident_rate=(blocked / n) if n else 0.0,
        redaction_rate=(redacted / n) if n else 0.0,
        approval_rate=(approvals_required / n) if n else 0.0,
        throttle_rate=(throttled / n) if n else 0.0,
        time_to_first_block_s=(first_block - first_t)
        if (first_block is not None and first_t is not None)
        else None,
        mean_evaluation_ms=(sum(eval_ms) / len(eval_ms)) if eval_ms else None,
        by_action=dict(by_action),
        by_rail=dict(by_rail),
        by_agent=dict(by_agent),
        approvals_granted=approvals,
    )


def policy_recall(records: Iterable[EvidenceRecord], labels: Mapping[str, bool]) -> float | None:
    """Share of calls labelled as violations (``labels[call_id] = True``) that were blocked."""
    decisions = {r.call_id: r for r in records if r.kind == "decision" and r.call_id}
    violating = [cid for cid, is_violation in labels.items() if is_violation and cid in decisions]
    if not violating:
        return None
    caught = sum(
        1
        for cid in violating
        if decisions[cid].action and PolicyAction(decisions[cid].action) not in PERMISSIVE
    )
    return caught / len(violating)
