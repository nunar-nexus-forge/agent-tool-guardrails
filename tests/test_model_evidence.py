from __future__ import annotations

import json

import pytest

from typed_rails import (
    ActionSpec,
    CallContext,
    Decision,
    EvidenceSpec,
    EvidenceStore,
    Phase,
    PolicyAction,
    PolicyDenied,
    Rail,
    RailEvaluation,
    RailType,
    Selector,
    most_severe,
)
from typed_rails.evidence import GENESIS, EvidenceRecord


def test_action_and_evidence_parsing():
    assert ActionSpec.parse(None).action is PolicyAction.DENY
    assert ActionSpec.parse("allow").action is PolicyAction.ALLOW
    spec = ActionSpec.parse(
        {"action": "redact", "fields": "args.x", "message": "m", "retry_after_s": 2, "kinds": ["email"]}
    )
    assert (
        spec.fields == ["args.x"]
        and spec.params == {"kinds": ["email"]}
        and spec.to_dict()["retry_after_s"] == 2
    )
    assert ActionSpec.parse(PolicyAction.LOG).action is PolicyAction.LOG
    with pytest.raises(ValueError):
        ActionSpec.parse(42)
    assert EvidenceSpec.parse("k").required == ["k"] and EvidenceSpec.parse(["a", "b"]).required == ["a", "b"]
    assert EvidenceSpec.parse({"required": "r", "capture": ["args.x"]}).to_dict() == {
        "required": ["r"],
        "capture": ["args.x"],
    }
    with pytest.raises(ValueError):
        EvidenceSpec.parse(3)
    assert most_severe([PolicyAction.LOG, PolicyAction.DENY, PolicyAction.REDACT]) is PolicyAction.DENY
    assert most_severe([]) is PolicyAction.ALLOW


def test_selector_and_rail_roundtrip():
    sel = Selector(tools=["search*"], agents=["junior", "senior"], phases=[Phase.PRE, Phase.POST])
    assert sel.matches("search_web", "junior", Phase.POST) and not sel.matches("browse", "junior", Phase.PRE)
    assert not sel.matches("search", "boss", Phase.PRE)
    from typed_rails import Predicate

    rail = Rail(
        "r1", RailType.from_dict({"risk": "privacy"}), Predicate("args.x > 1"), selector=sel, citation="c"
    )
    back = Rail.from_dict(json.loads(json.dumps(rail.to_dict())))
    assert (
        back.id == "r1"
        and back.type.label == "privacy/tool"
        and back.predicate == rail.predicate
        and back.citation == "c"
    )
    assert back.selector.to_dict() == sel.to_dict() and not back.is_static
    assert Rail("s", RailType.from_dict({}), Predicate("false")).is_static


def test_call_context_namespace_and_phase():
    ctx = CallContext(tool="t", args={"a": 1}, agent="bot", agent_trust=0.5, evidence={"e": 1}, timestamp=0.0)
    ns = ctx.namespace()
    assert (
        ns["agent"] == {"name": "bot", "trust": 0.5, "role": None}
        and ns["time"]["hour"] == 0
        and ns["phase"] == "pre"
    )
    assert ctx.namespace(trust=0.9)["agent"]["trust"] == 0.9
    post = ctx.with_phase(Phase.POST, result="r")
    assert (
        post.phase is Phase.POST
        and post.result == "r"
        and post.call_id == ctx.call_id
        and post.args is ctx.args
    )


def test_decision_explain_and_errors():
    ev = RailEvaluation(
        "r", "privacy/tool", False, PolicyAction.DENY, missing_evidence=["k"], citation="GDPR", error="boom"
    )
    d = Decision(
        "c",
        "t",
        "a",
        Phase.PRE,
        PolicyAction.DENY,
        False,
        [ev],
        reasons=["r: nope"],
        governance={"level": "normal"},
    )
    text = d.explain()
    assert (
        "DENY a -> t" in text
        and "missing evidence: k" in text
        and "(GDPR)" in text
        and "error: boom" in text
        and "governance" in text
    )
    assert d.blocked and d.failed_rails == [ev] and d.to_dict()["action"] == "deny"
    err = PolicyDenied(d)
    assert err.decision is d and "nope" in str(err)


def test_evidence_chain_and_tamper_detection(tmp_path):
    path = tmp_path / "evidence.jsonl"
    store = EvidenceStore(path, hmac_key="secret")
    r0 = store.append(
        "decision", agent="a", tool="t", action="allow", allowed=True, rails=[], payload={"x": 1}
    )
    r1 = store.append("note", payload={"m": "hello"})
    assert r0.prev_hash == GENESIS and r1.prev_hash == r0.hash and r0.signature and store.last_hash == r1.hash
    assert store.verify().ok and len(store) == 2 and store.merkle_root() != GENESIS
    reloaded = EvidenceStore.load(path, hmac_key="secret")
    assert reloaded.verify().ok and [r.index for r in reloaded] == [0, 1]
    assert EvidenceStore.load(path).verify(hmac_key="wrong").ok is False
    # tamper with the file
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["payload"]["x"] = 2
    path.write_text("\n".join([json.dumps(rec), lines[1]]) + "\n")
    bad = EvidenceStore.load(path, hmac_key="secret").verify()
    assert not bad.ok and bad.first_invalid == 0 and "hash" in (bad.reason or "") and "TAMPERED" in str(bad)
    # remove a record -> chain link broken
    path.write_text(lines[1] + "\n")
    bad2 = EvidenceStore.load(path).verify()
    assert not bad2.ok and bad2.reason == "index 1 != position 0"
    exported = store.export(tmp_path / "copy.jsonl")
    assert EvidenceStore.load(exported, hmac_key="secret").verify().ok
    assert (
        store.query(agent="a")[0] is r0
        and store.query(kind="note") == [r1]
        and store.query(tool="nope") == []
    )
    assert EvidenceRecord.from_dict({"index": 0, "t": 0, "kind": "x", "unknown": 1}).kind == "x"
    assert EvidenceStore().merkle_root() == GENESIS
