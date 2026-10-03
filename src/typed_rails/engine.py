# SPDX-License-Identifier: Apache-2.0
"""The Policy Engine: evaluates rails for a call, combines their actions, applies
redactions, records evidence and feeds the trust-scored governance loop."""

from __future__ import annotations

import functools
import inspect
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .compiler import RailSet
from .evidence import EvidenceStore, digest
from .metrics import GovernanceMetrics, compute_metrics
from .model import (
    PERMISSIVE,
    ApprovalRequired,
    CallContext,
    Decision,
    Phase,
    PolicyAction,
    PolicyDenied,
    Rail,
    RailEvaluation,
    Throttled,
    most_severe,
)
from .predicates import PredicateError, resolve_path
from .redaction import redact_value
from .trust import GovernanceLoop

ApprovalHandler = Callable[[CallContext, Decision], bool]


@dataclass
class EngineConfig:
    fail_closed: bool = True
    record_args: bool = True
    record_results: bool = False
    governance_enforcement: bool = True
    rate_window_max_s: float = 3600.0


class PolicyEngine:
    def __init__(
        self,
        rails: RailSet,
        *,
        evidence: EvidenceStore | None = None,
        governance: GovernanceLoop | None = None,
        approval_handler: ApprovalHandler | None = None,
        static_evidence: Mapping[str, Any] | None = None,
        trust_fn: Callable[[str], float] | None = None,
        config: EngineConfig | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.rails = rails
        self.evidence = evidence if evidence is not None else EvidenceStore()
        self.governance = governance if governance is not None else GovernanceLoop()
        self.approval_handler = approval_handler
        self.static_evidence = dict(static_evidence or {})
        self.trust_fn = trust_fn
        self.config = config or EngineConfig()
        self._clock = clock
        self._calls: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.decisions: list[Decision] = []

    # -- helpers -------------------------------------------------------------------

    def now(self) -> float:
        """Current time according to the engine's clock (``time.time`` unless one was injected).

        Guarded calls and the MCP proxy stamp their :class:`CallContext` with this clock, so the
        ``time.*`` predicate namespace can be pinned in tests and demos.
        """
        return self._clock()

    def rate(self, agent: str, tool: str, window_s: float = 60.0) -> int:
        """Calls (attempted) by ``agent`` on ``tool`` within the last ``window_s`` seconds."""
        now = self._clock()
        q = self._calls[(agent, tool)]
        while q and now - q[0] > self.config.rate_window_max_s:
            q.popleft()
        return sum(1 for t in q if now - t <= window_s)

    def _note_call(self, agent: str, tool: str) -> None:
        self._calls[(agent, tool)].append(self._clock())

    def _trust(self, ctx: CallContext) -> float:
        if ctx.agent_trust is not None:
            return ctx.agent_trust
        if self.trust_fn is not None:
            return float(self.trust_fn(ctx.agent))
        return self.governance.trust.get(ctx.agent)

    def _functions(self, ctx: CallContext) -> dict[str, Callable[..., Any]]:
        def rate(tool: Any = None, window: Any = 60.0) -> int:
            return self.rate(ctx.agent, str(tool) if tool else ctx.tool, float(window or 60.0))

        return {"rate": rate}

    # -- evaluation ------------------------------------------------------------------

    def evaluate(self, ctx: CallContext) -> Decision:
        """Pre-condition evaluation of a call (or post-condition when ``ctx.phase`` is POST)."""
        return self._evaluate(ctx, self.rails.applicable(ctx.tool, ctx.agent, ctx.phase), record=True)

    def evaluate_result(self, ctx: CallContext, result: Any) -> Decision:
        """Post-condition evaluation of a call's result."""
        post = ctx.with_phase(Phase.POST, result)
        return self._evaluate(post, self.rails.applicable(post.tool, post.agent, Phase.POST), record=True)

    def _evaluate(self, ctx: CallContext, rails: Iterable[Rail], *, record: bool) -> Decision:
        start = time.perf_counter()
        if self.static_evidence:
            merged = dict(self.static_evidence)
            merged.update(ctx.evidence)
            ctx.evidence = merged
        ns = ctx.namespace(trust=self._trust(ctx))
        ns["env"] = {**ns["env"], "strictness": self.governance.strictness}
        functions = self._functions(ctx)
        evaluations: list[RailEvaluation] = []
        reasons: list[str] = []
        for rail in rails:
            missing = [
                k for k in rail.evidence.required if resolve_path(ns["evidence"], tuple(k.split("."))) is None
            ]
            error: str | None = None
            if missing:
                passed = False
            else:
                try:
                    passed = rail.predicate.evaluate(ns, functions)
                except PredicateError as exc:
                    error = str(exc)
                    passed = not self.config.fail_closed
            spec = rail.on_pass if passed else rail.on_fail
            seen = rail.predicate.explain(ns)
            for path in rail.evidence.capture:
                seen[path] = resolve_path(ns, tuple(path.split(".")))
            seen, _ = redact_value(seen, None, detect=True)
            evaluations.append(
                RailEvaluation(
                    rail_id=rail.id,
                    type=rail.type.label,
                    passed=passed,
                    action=spec.action,
                    evidence_seen=seen,
                    missing_evidence=missing,
                    message=spec.message,
                    error=error,
                    citation=rail.citation,
                )
            )
            if not passed:
                why = spec.message or f"predicate {rail.predicate.source!r} is false"
                if missing:
                    why = f"missing evidence {', '.join(missing)}"
                if error:
                    why = f"predicate error: {error}"
                reasons.append(f"{rail.id}: {why}")

        action = most_severe(e.action for e in evaluations)
        governance_state: dict[str, Any] | None = None
        if self.config.governance_enforcement and record and ctx.phase == Phase.PRE:
            level = self.governance.level(ctx.agent)
            if level == "isolate":
                action = most_severe([action, PolicyAction.QUARANTINE])
                reasons.append(f"governance: agent {ctx.agent} isolated (fusion score below threshold)")
            elif level == "throttle":
                action = most_severe([action, PolicyAction.THROTTLE])
                reasons.append(f"governance: agent {ctx.agent} throttled (fusion score below threshold)")

        redactions: list[str] = []
        args = ctx.args
        result = ctx.result
        if action in PERMISSIVE:
            redact_specs = [
                rail.on_pass if ev.passed else rail.on_fail
                for rail, ev in zip(rails, evaluations)
                if ev.action == PolicyAction.REDACT
            ]
            for spec in redact_specs:
                fields = list(spec.fields)
                kinds = spec.params.get("kinds")
                if ctx.phase == Phase.PRE:
                    target_fields = [f for f in fields if not f.startswith("result")] or None
                    if target_fields is not None or spec.detect_pii:
                        args, paths = redact_value(args, target_fields, detect=spec.detect_pii, kinds=kinds)
                        redactions.extend(f"args.{p}" if p != "$" else "args" for p in paths)
                else:
                    target_fields = [f for f in fields if f.startswith("result")] or None
                    result, paths = redact_value(result, target_fields, detect=spec.detect_pii, kinds=kinds)
                    redactions.extend(f"result.{p}" if p != "$" else "result" for p in paths)
        allowed = action in PERMISSIVE
        retry_after = None
        if action == PolicyAction.THROTTLE:
            retry_after = next(
                (
                    rail.on_fail.retry_after_s
                    for rail, ev in zip(rails, evaluations)
                    if ev.action == PolicyAction.THROTTLE and rail.on_fail.retry_after_s
                ),
                None,
            )

        if record and ctx.phase == Phase.PRE:
            self._note_call(ctx.agent, ctx.tool)
            state = self.governance.record_decision(ctx.agent, allowed)
            governance_state = state.to_dict()

        decision = Decision(
            call_id=ctx.call_id,
            tool=ctx.tool,
            agent=ctx.agent,
            phase=ctx.phase,
            action=action,
            allowed=allowed,
            evaluations=evaluations,
            redactions=list(dict.fromkeys(redactions)),
            args=args,
            result=result,
            reasons=reasons,
            approval_required=action == PolicyAction.REQUIRE_APPROVAL,
            throttled=action == PolicyAction.THROTTLE,
            retry_after_s=retry_after,
            evaluated_at=self._clock(),
            evaluation_ms=(time.perf_counter() - start) * 1000.0,
            governance=governance_state,
        )
        if record:
            payload: dict[str, Any] = {
                "evaluation_ms": round(decision.evaluation_ms, 4),
                "reasons": list(reasons),
            }
            if self.config.record_args and ctx.phase == Phase.PRE:
                payload["args"], _ = redact_value(args, None, detect=True)
            if self.config.record_results and ctx.phase == Phase.POST:
                payload["result"], _ = redact_value(result, None, detect=True)
            if ctx.evidence:
                payload["evidence"], _ = redact_value(ctx.evidence, None, detect=True)
            rec = self.evidence.append(
                "decision",
                t=decision.evaluated_at,
                call_id=ctx.call_id,
                agent=ctx.agent,
                tool=ctx.tool,
                phase=ctx.phase.value,
                action=action.value,
                allowed=allowed,
                rails=[e.to_dict() for e in evaluations],
                args_digest=digest(ctx.args) if ctx.phase == Phase.PRE else None,
                result_digest=digest(ctx.result)
                if ctx.phase == Phase.POST and ctx.result is not None
                else None,
                redactions=list(decision.redactions),
                payload=payload,
                policy_hash=self.rails.policy_hash,
            )
            decision.evidence_index = rec.index
            self.decisions.append(decision)
        return decision

    # -- approvals -------------------------------------------------------------------

    def approve(self, decision: Decision, approver: str, note: str = "") -> Decision:
        """Record a human approval for a REQUIRE_APPROVAL decision and mark it allowed."""
        self.evidence.append(
            "approval",
            call_id=decision.call_id,
            agent=decision.agent,
            tool=decision.tool,
            phase=decision.phase.value,
            action=PolicyAction.ALLOW.value,
            allowed=True,
            payload={"approver": approver, "note": note},
            policy_hash=self.rails.policy_hash,
        )
        decision.allowed = True
        decision.approval_required = False
        decision.action = PolicyAction.ALLOW
        decision.reasons.append(f"approved by {approver}")
        return decision

    def request_approval(self, ctx: CallContext, decision: Decision) -> bool:
        if self.approval_handler is None:
            return False
        if self.approval_handler(ctx, decision):
            self.approve(decision, approver="approval_handler")
            return True
        return False

    # -- static analysis ---------------------------------------------------------------

    def statically_denied_tools(self, tools: Iterable[str], agent: str) -> list[str]:
        """Tools an agent can never call regardless of arguments or evidence (for hiding them)."""
        denied: list[str] = []
        for tool in tools:
            rails = [r for r in self.rails.applicable(tool, agent, Phase.PRE) if r.is_static]
            if not rails:
                continue
            ctx = CallContext(tool=tool, agent=agent)
            decision = self._evaluate(ctx, rails, record=False)
            if decision.action in (PolicyAction.DENY, PolicyAction.QUARANTINE):
                denied.append(tool)
        return denied

    # -- guard --------------------------------------------------------------------------

    def guard(
        self,
        tool: str | None = None,
        *,
        agent: str | Callable[[], str] = "agent",
        evidence: Mapping[str, Any] | Callable[[], Mapping[str, Any]] | None = None,
        session: Mapping[str, Any] | None = None,
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorate a Python tool function so every call is evaluated (pre and post)."""

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            name: str = tool or str(getattr(fn, "__name__", "tool"))
            sig = inspect.signature(fn)

            def _context(
                args: tuple[Any, ...], kwargs: dict[str, Any]
            ) -> tuple[CallContext, inspect.BoundArguments]:
                bound = sig.bind_partial(*args, **kwargs)
                call_args = dict(bound.arguments)
                agent_name = agent() if callable(agent) else agent
                ev = evidence() if callable(evidence) else dict(evidence or {})
                ctx = CallContext(
                    tool=name,
                    args=call_args,
                    agent=agent_name,
                    evidence=dict(ev),
                    session=dict(session or {}),
                    timestamp=self._clock(),
                )
                return ctx, bound

            def _before(
                args: tuple[Any, ...], kwargs: dict[str, Any]
            ) -> tuple[CallContext, inspect.BoundArguments]:
                ctx, bound = _context(args, kwargs)
                decision = self.evaluate(ctx)
                if decision.approval_required and not self.request_approval(ctx, decision):
                    raise ApprovalRequired(decision)
                if decision.throttled:
                    raise Throttled(decision)
                if not decision.allowed:
                    raise PolicyDenied(decision)
                for key, value in decision.args.items():
                    if key in bound.arguments:
                        bound.arguments[key] = value
                return ctx, bound

            def _after(ctx: CallContext, result: Any) -> Any:
                if not self.rails.applicable(ctx.tool, ctx.agent, Phase.POST):
                    return result
                decision = self.evaluate_result(ctx, result)
                if not decision.allowed:
                    raise PolicyDenied(decision)
                return decision.result if decision.redactions else result

            if inspect.iscoroutinefunction(fn):

                @functools.wraps(fn)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    ctx, bound = _before(args, kwargs)
                    return _after(ctx, await fn(*bound.args, **bound.kwargs))

                return async_wrapper

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx, bound = _before(args, kwargs)
                return _after(ctx, fn(*bound.args, **bound.kwargs))

            return wrapper

        return decorate

    # -- reporting ----------------------------------------------------------------------

    def metrics(self) -> GovernanceMetrics:
        return compute_metrics(self.evidence.records())
