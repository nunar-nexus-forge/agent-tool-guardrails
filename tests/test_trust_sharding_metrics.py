from __future__ import annotations

import pytest

from typed_rails import (
    ComplianceTracker,
    GovernanceConfig,
    GovernanceLoop,
    Shard,
    ShardAccessDenied,
    ShardedMemory,
    ShardPolicy,
    TrustModel,
)
from typed_rails.evidence import EvidenceStore
from typed_rails.metrics import compute_metrics, policy_recall


def test_governance_config_validation():
    with pytest.raises(ValueError):
        GovernanceConfig(lam=1.5)
    with pytest.raises(ValueError):
        GovernanceConfig(throttle_below=0.3, isolate_below=0.5)


def test_trust_model_and_compliance():
    cfg = GovernanceConfig(lam=0.5, gamma=0.5, alpha=0.5, initial_trust=0.6)
    trust = TrustModel(cfg)
    assert trust.get("a") == 0.6
    assert trust.update("a", 1.0) == pytest.approx(0.8)
    assert trust.update("a", 0.0) == pytest.approx(0.4)
    assert trust.update_pair("a", "b", 1.0) == pytest.approx(0.8) and trust.update_pair(
        "a", "c", 0.0
    ) == pytest.approx(0.3)
    w = trust.privilege_weights("a")
    assert (
        w["b"] == pytest.approx(0.8 / 1.1)
        and abs(sum(w.values()) - 1.0) < 1e-9
        and trust.privilege_weights("z") == {}
    )
    assert trust.fusion("a", compliance=1.0) == pytest.approx(0.5 * 1.0 + 0.5 * 0.4)
    tracker = ComplianceTracker(window=3)
    assert tracker.score("a") == 1.0
    tracker.record("a", True)
    tracker.record("a", False)
    tracker.record("a", False)
    tracker.record("a", False)
    assert tracker.score("a") == 0.0 and tracker.actions("a") == 3 and tracker.violations["a"] == 3


def test_governance_loop_levels_and_adaptation():
    loop = GovernanceLoop(
        GovernanceConfig(
            lam=0.5,
            alpha=0.5,
            window=4,
            throttle_below=0.7,
            isolate_below=0.4,
            initial_trust=1.0,
            adapt_sensitivity=0.5,
        )
    )
    assert loop.level("a") == "normal"
    for _ in range(3):
        state = loop.record_decision("a", False)
    assert state.level in ("throttle", "isolate") and state.compliance == 0.25 and state.actions == 3
    loop.evidence("a", 1.0)
    assert loop.trust.get("a") > 0.1
    assert loop.adapt(1.0) == 0.5 and loop.adapt(-2.0) == 0.0
    loop.enabled = False
    assert loop.level("a") == "normal"


def test_sharded_memory_policy():
    penalised = []
    policy = ShardPolicy(
        rules={"policy": ["governor"], "context": ["*"], "analytics": ["analyst*", "governor"]},
        write_rules={"analytics": ["governor"]},
        min_trust={"context": 0.5},
        predicate='not (op == "delete" and shard == "context")',
    )
    trust = {"analyst-1": 0.9, "intruder": 0.1, "governor": 1.0}
    mem = ShardedMemory(
        "agent-7",
        policy,
        trust_fn=lambda p: trust.get(p, 1.0),
        on_violation=lambda a: penalised.append(a.process),
    )
    mem.write("governor", Shard.POLICY, "max_amount", 1000)
    assert mem.read("governor", "policy", "max_amount") == 1000
    with pytest.raises(ShardAccessDenied) as info:
        mem.read("analyst-1", Shard.POLICY, "max_amount")
    assert "not allowed" in str(info.value) and penalised == ["analyst-1"]
    mem.write("analyst-1", Shard.CONTEXT, "temp", 20.0)
    assert mem.update_context("analyst-1", "temp", 30.0, beta=0.5) == 25.0
    assert mem.update_context("analyst-1", "vec", [1.0, 1.0]) == [1.0, 1.0]
    assert mem.update_context("analyst-1", "vec", [3.0, 3.0], beta=0.5) == [2.0, 2.0]
    with pytest.raises(ShardAccessDenied):
        mem.read("intruder", Shard.CONTEXT, "temp")  # trust below 0.5
    with pytest.raises(ShardAccessDenied):
        mem.delete("analyst-1", Shard.CONTEXT, "temp")  # predicate forbids deletes
    assert mem.read("analyst-1", Shard.ANALYTICS, "kpi", default=0) == 0
    with pytest.raises(ShardAccessDenied):
        mem.write("analyst-1", Shard.ANALYTICS, "kpi", 1)  # write rule
    mem.write("governor", Shard.ANALYTICS, "kpi", 1)
    mem.delete("governor", Shard.ANALYTICS, "kpi")
    assert len(mem.violations) == 4 and 0 < mem.compliance() < 1 and mem.lineage("temp")[0]["op"] == "write"
    assert ShardedMemory("x").read("anyone", "context", "k") is None


def test_metrics_and_policy_recall():
    store = EvidenceStore()
    store.append(
        "decision",
        t=10.0,
        call_id="c1",
        agent="a",
        tool="t",
        phase="pre",
        action="allow",
        allowed=True,
        rails=[{"rail_id": "r", "passed": True}],
        payload={"evaluation_ms": 0.5},
    )
    store.append(
        "decision",
        t=12.0,
        call_id="c2",
        agent="a",
        tool="t",
        phase="pre",
        action="deny",
        allowed=False,
        rails=[{"rail_id": "r", "passed": False}],
        payload={"evaluation_ms": 1.5},
    )
    store.append(
        "decision",
        t=13.0,
        call_id="c3",
        agent="b",
        tool="u",
        phase="pre",
        action="require_approval",
        allowed=False,
        rails=[],
        payload={},
    )
    store.append(
        "decision",
        t=14.0,
        call_id="c4",
        agent="b",
        tool="u",
        phase="pre",
        action="redact",
        allowed=True,
        rails=[{"rail_id": "p", "passed": False}],
        redactions=["args.x"],
        payload={},
    )
    store.append("approval", call_id="c3", agent="b", tool="u", action="allow", allowed=True)
    m = compute_metrics(store.records())
    assert (
        m.decisions == 4
        and m.blocked == 2
        and m.allowed == 2
        and m.coverage == 0.75
        and m.redaction_rate == 0.25
    )
    assert (
        m.approval_rate == 0.25
        and m.time_to_first_block_s == 2.0
        and m.mean_evaluation_ms == 1.0
        and m.approvals_granted == 1
    )
    assert m.by_rail == {"r": {"evaluations": 2, "failed": 1}, "p": {"evaluations": 1, "failed": 1}}
    assert policy_recall(store.records(), {"c1": False, "c2": True, "c3": True, "c4": True}) == pytest.approx(
        2 / 3
    )
    assert policy_recall(store.records(), {"c1": False}) is None
    assert compute_metrics([]).decisions == 0 and "n/a" in compute_metrics([]).to_markdown()
