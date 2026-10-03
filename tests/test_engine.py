from __future__ import annotations

import asyncio

import pytest

from typed_rails import (
    ApprovalRequired,
    CallContext,
    EngineConfig,
    EvidenceStore,
    GovernanceConfig,
    GovernanceLoop,
    PolicyAction,
    PolicyDenied,
    PolicyEngine,
    Throttled,
    compile_policy,
)


def test_allow_deny_and_evidence_recording(engine):
    ok = engine.evaluate(CallContext(tool="transfer_funds", args={"amount": 50}, agent="bot"))
    assert (
        ok.allowed
        and ok.action is PolicyAction.ALLOW
        and ok.evidence_index == 0
        and ok.governance["level"] == "normal"
    )
    denied = engine.evaluate(CallContext(tool="drop_database", agent="bot"))
    assert (
        denied.blocked
        and denied.action is PolicyAction.DENY
        and denied.reasons == ["no-drop: tool is denied by policy"]
    )
    records = engine.evidence.records()
    assert [r.action for r in records] == ["allow", "deny"] and records[1].rails[0]["rail_id"] == "no-drop"
    assert records[0].policy_hash == engine.rails.policy_hash and records[0].payload["args"] == {"amount": 50}
    assert engine.evidence.verify().ok
    assert engine.evaluate(CallContext(tool="unknown_tool", agent="bot")).allowed  # no applicable rail


def test_missing_evidence_and_redaction(engine):
    ctx = CallContext(
        tool="export_report",
        args={"customer": {"email": "a@b.com", "name": "Jane"}, "note": "ok"},
        agent="analyst",
    )
    d = engine.evaluate(ctx)
    assert (
        d.allowed and d.action is PolicyAction.REDACT and d.evaluations[0].missing_evidence == ["anonymised"]
    )
    assert d.args["customer"] == {"email": "[REDACTED]", "name": "[REDACTED]"} and d.args["note"] == "ok"
    assert d.redactions == ["args.customer.email", "args.customer.name"]
    assert ctx.args["customer"]["email"] == "a@b.com"
    ok = engine.evaluate(
        CallContext(
            tool="export_report",
            args={"customer": {"email": "a@b.com"}},
            agent="analyst",
            evidence={"anonymised": True},
        )
    )
    assert (
        ok.action is PolicyAction.ALLOW
        and ok.redactions == []
        and ok.evaluations[0].evidence_seen == {"evidence.anonymised": True}
    )
    rec = engine.evidence.records()[-1]
    assert rec.payload["evidence"] == {"anonymised": True}


def test_pii_detection_redaction_pre_and_post(engine):
    d = engine.evaluate(CallContext(tool="echo", args={"text": "mail me at jane@example.com"}, agent="bot"))
    assert (
        d.action is PolicyAction.REDACT
        and d.args["text"] == "mail me at [REDACTED:email]"
        and d.redactions == ["args.text"]
    )
    ctx = CallContext(tool="lookup", args={"q": "jane"}, agent="bot")
    pre = engine.evaluate(ctx)
    assert pre.allowed and pre.action is PolicyAction.ALLOW
    post = engine.evaluate_result(ctx, "Jane Doe, 555-123-4567")
    assert post.allowed and post.result == "Jane Doe, [REDACTED:phone]" and post.redactions == ["result"]
    post_struct = engine.evaluate_result(ctx, {"phone": "555-123-4567", "n": 1})
    assert post_struct.result == {"phone": "[REDACTED:phone]", "n": 1}


def test_approval_and_throttle(engine):
    d = engine.evaluate(CallContext(tool="transfer_funds", args={"amount": 5000}, agent="bot"))
    assert d.approval_required and not d.allowed and d.action is PolicyAction.REQUIRE_APPROVAL
    approved = engine.approve(d, approver="cfo", note="ok")
    assert (
        approved.allowed
        and approved.action is PolicyAction.ALLOW
        and engine.evidence.records()[-1].kind == "approval"
    )
    for _ in range(3):
        assert engine.evaluate(CallContext(tool="search", args={"q": "x"}, agent="bot")).allowed
    throttled = engine.evaluate(CallContext(tool="search", args={"q": "x"}, agent="bot"))
    assert (
        throttled.throttled and throttled.retry_after_s == 60.0 and throttled.action is PolicyAction.THROTTLE
    )
    assert engine.rate("bot", "search", 60) == 4 and engine.rate("other", "search") == 0


def test_trust_gate_uses_governance_or_explicit_trust(engine):
    assert engine.evaluate(CallContext(tool="execute_code", agent="bot", agent_trust=0.9)).allowed
    assert engine.evaluate(CallContext(tool="execute_code", agent="bot", agent_trust=0.2)).blocked
    engine.governance.trust.set("bot", 0.95)
    assert engine.evaluate(CallContext(tool="execute_code", agent="bot")).allowed
    engine2 = PolicyEngine(engine.rails, trust_fn=lambda a: 0.1)
    assert engine2.evaluate(CallContext(tool="execute_code", agent="bot")).blocked


def test_forbidden_patterns_and_allowed_tools(engine):
    assert engine.evaluate(CallContext(tool="query", args={"sql": "select 1"}, agent="bot")).allowed
    assert engine.evaluate(CallContext(tool="query", args={"sql": "DROP TABLE users"}, agent="bot")).blocked
    assert engine.evaluate(CallContext(tool="search", args={"q": "x"}, agent="junior")).allowed
    denied = engine.evaluate(CallContext(tool="transfer_funds", args={"amount": 1}, agent="junior"))
    assert denied.blocked and denied.failed_rails[0].rail_id == "junior-tools"
    assert engine.statically_denied_tools(["transfer_funds", "search", "drop_database"], "junior") == [
        "transfer_funds",
        "drop_database",
    ]
    assert engine.statically_denied_tools(["transfer_funds", "search", "drop_database"], "bot") == [
        "drop_database"
    ]


def test_governance_escalation(rails):
    gov = GovernanceLoop(
        GovernanceConfig(
            lam=0.5, alpha=0.5, window=5, throttle_below=0.9, isolate_below=0.5, initial_trust=1.0
        )
    )
    engine = PolicyEngine(rails, governance=gov)
    for _ in range(4):
        engine.evaluate(CallContext(tool="drop_database", agent="rogue"))
    d = engine.evaluate(CallContext(tool="search", args={"q": "x"}, agent="rogue"))
    assert d.action in (PolicyAction.THROTTLE, PolicyAction.QUARANTINE) and d.governance["level"] in (
        "throttle",
        "isolate",
    )
    assert any("governance" in r for r in d.reasons)
    snap = gov.snapshot()
    assert "rogue" in snap["agents"] and snap["agents"]["rogue"]["compliance"] < 0.5
    gov.reset("rogue")
    assert gov.level("rogue") == "normal"
    engine_off = PolicyEngine(rails, governance=gov, config=EngineConfig(governance_enforcement=False))
    assert engine_off.evaluate(CallContext(tool="search", args={"q": "x"}, agent="rogue")).allowed


def test_guard_decorator(engine):
    calls = []

    @engine.guard("transfer_funds", agent="treasury")
    def transfer_funds(amount, to="x"):
        calls.append((amount, to))
        return f"sent {amount} to {to}"

    assert transfer_funds(10, to="acme") == "sent 10 to acme"
    with pytest.raises(ApprovalRequired):
        transfer_funds(5000)
    engine.approval_handler = lambda ctx, d: True
    assert transfer_funds(5000) == "sent 5000 to x"
    engine.approval_handler = lambda ctx, d: False
    with pytest.raises(ApprovalRequired):
        transfer_funds(5000)

    @engine.guard("drop_database")
    def drop():
        return "dropped"

    with pytest.raises(PolicyDenied):
        drop()

    @engine.guard("echo")
    def echo(text):
        return text

    assert echo("mail a@b.com") == "mail [REDACTED:email]"  # arguments redacted before the call

    @engine.guard("lookup")
    def lookup(q):
        return "phone 555-123-4567"

    assert lookup("jane") == "phone [REDACTED:phone]"  # result redacted after the call

    @engine.guard("search", agent="bot2")
    async def search(q):
        return [q]

    assert asyncio.run(search("x")) == ["x"]
    for _ in range(3):
        try:
            asyncio.run(search("x"))
        except Throttled:
            break
    else:  # pragma: no cover
        raise AssertionError("expected throttling")


def test_fail_closed_on_predicate_error(tmp_path):
    rails = compile_policy(
        {
            "version": 1,
            "name": "t",
            "requirements": [{"id": "r", "tools": ["t"], "predicate": 'matches(args.x, "(")'}],
        }
    )
    store = EvidenceStore(tmp_path / "e.jsonl")
    engine = PolicyEngine(rails, evidence=store)
    d = engine.evaluate(CallContext(tool="t", args={"x": "y"}))
    assert d.blocked and d.evaluations[0].error and "predicate error" in d.reasons[0]
    open_engine = PolicyEngine(rails, config=EngineConfig(fail_closed=False))
    assert open_engine.evaluate(CallContext(tool="t", args={"x": "y"})).allowed
    assert (tmp_path / "e.jsonl").exists() and store.verify().ok


def test_metrics_from_engine(engine):
    engine.evaluate(CallContext(tool="drop_database", agent="bot"))
    engine.evaluate(CallContext(tool="search", args={"q": "x"}, agent="bot"))
    m = engine.metrics()
    assert m.decisions == 2 and m.blocked == 1 and m.coverage == 1.0 and m.safety_incident_rate == 0.5
    assert (
        m.by_rail["no-drop"]["failed"] == 1
        and m.by_agent["bot"]["blocked"] == 1
        and m.time_to_first_block_s == 0.0
    )
    md = m.to_markdown()
    assert "safety incident rate" in md and "| no-drop |" in md


def test_guard_and_proxy_use_engine_clock_for_time_predicates():
    import datetime as dt

    from typed_rails.mcp_proxy import MCPMessageInterceptor

    policy = """
version: 1
name: clock
requirements:
  - template: time_window
    id: office-hours
    tools: [transfer_funds]
    hours: [7, 20]
    weekdays: [0, 1, 2, 3, 4]
"""
    tuesday = dt.datetime(2026, 9, 29, 10, 0, tzinfo=dt.timezone.utc).timestamp()
    sunday = dt.datetime(2026, 9, 27, 10, 0, tzinfo=dt.timezone.utc).timestamp()
    now = {"t": tuesday}
    engine = PolicyEngine(compile_policy(policy), clock=lambda: now["t"])
    assert engine.now() == tuesday

    @engine.guard("transfer_funds", agent="bot")
    def transfer_funds(amount: float) -> str:
        return f"ok {amount}"

    assert transfer_funds(10) == "ok 10"
    now["t"] = sunday
    with pytest.raises(PolicyDenied):
        transfer_funds(10)
    assert engine.decisions[-1].evaluated_at == sunday

    icp = MCPMessageInterceptor(engine, agent="bot")
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "transfer_funds", "arguments": {"amount": 1}},
    }
    fwd, reply = icp.on_client_message(call)
    assert fwd is None and reply is not None and reply["result"]["isError"]  # still Sunday
    now["t"] = tuesday
    fwd, reply = icp.on_client_message({**call, "id": 2})
    assert reply is None and fwd is not None


def test_approval_does_not_alter_hashed_evidence(engine):
    decision = engine.evaluate(CallContext(tool="transfer_funds", args={"amount": 5000}, agent="bot"))
    assert decision.approval_required and engine.evidence.verify().ok
    engine.approve(decision, approver="cfo", note="quarter-end payment")
    assert decision.allowed and "approved by cfo" in decision.reasons
    assert engine.evidence.verify().ok  # the hashed decision record must not change after approval
    first = engine.evidence.records()[0]
    assert first.payload["reasons"] == ["big-transfers: args.amount above 1000 needs human approval"]
    assert engine.evidence.records()[1].kind == "approval"
