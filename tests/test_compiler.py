from __future__ import annotations

import json

import pytest

from typed_rails import TEMPLATES, PolicyAction, PolicyCompileError, RailSet, compile_policy
from typed_rails.model import Phase


def test_compile_finance_policy(rails):
    assert rails.name == "finance" and len(rails.rails) == 9 and rails.policy_hash and rails.source_hash
    ids = [r.id for r in rails.rails]
    assert ids == [
        "gdpr-anonymised",
        "big-transfers",
        "no-drop",
        "search-rate",
        "code-trust",
        "echo-pii",
        "lookup-output",
        "no-sql-injection",
        "junior-tools",
    ]
    gdpr = rails.by_id("gdpr-anonymised")
    assert (
        gdpr.type.label == "privacy/tool"
        and gdpr.evidence.required == ["anonymised"]
        and gdpr.on_fail.action is PolicyAction.REDACT
    )
    assert (
        gdpr.on_fail.fields == ["args.customer.email", "args.customer.name"]
        and gdpr.citation == "GDPR Art. 5(1)(c)"
    )
    big = rails.by_id("big-transfers")
    assert (
        big.predicate.source == "args.amount == null or args.amount <= 1000"
        and big.on_fail.action is PolicyAction.REQUIRE_APPROVAL
    )
    assert rails.by_id("no-drop").is_static and rails.by_id("junior-tools").selector.agents == ["junior"]
    assert rails.by_id("lookup-output").selector.phases == [Phase.POST]
    assert rails.by_id("search-rate").on_fail.retry_after_s == 60.0
    assert "transfer_funds" in rails.tools()
    assert [r.id for r in rails.applicable("transfer_funds", "bot", Phase.PRE)] == ["big-transfers"]
    assert [r.id for r in rails.applicable("search", "junior", Phase.PRE)] == ["junior-tools", "search-rate"]
    with pytest.raises(KeyError):
        rails.by_id("nope")
    md = rails.explain()
    assert md.startswith("# Policy `finance`") and "| gdpr-anonymised |" in md


def test_compiled_roundtrip_and_hash_stability(rails, tmp_path):
    path = tmp_path / "finance.rails.json"
    rails.save(path)
    back = RailSet.load(path)
    assert back.policy_hash == rails.policy_hash and [r.to_dict() for r in back.rails] == [
        r.to_dict() for r in rails.rails
    ]
    again = compile_policy(
        json.loads(
            json.dumps({"version": 1, "name": "finance", "requirements": [{"id": "x", "predicate": "true"}]})
        )
    )
    assert (
        again.policy_hash
        == compile_policy(
            {"version": 1, "name": "finance", "requirements": [{"id": "x", "predicate": "true"}]}
        ).policy_hash
    )


def test_all_templates_compile():
    doc = {
        "version": 1,
        "name": "all",
        "requirements": [
            {"template": "allowed_tools", "agents": ["a"], "tools": ["x"]},
            {"template": "deny_tools", "tools": ["y"]},
            {"template": "approval_threshold", "tool": "pay", "threshold": 5, "inclusive": False},
            {"template": "rate_limit", "tools": ["s"], "max_calls": 2, "per_seconds": 10},
            {"template": "trust_gate", "tools": ["c"], "min_trust": 0.5},
            {"template": "pii_redaction", "fields": ["args.note"], "kinds": ["email"]},
            {"template": "output_pii_redaction"},
            {"template": "time_window", "tools": ["t"], "hours": [9, 17], "weekdays": [0, 1]},
            {"template": "data_residency", "allowed_regions": ["EU"]},
            {"template": "purpose_limitation", "allowed_purposes": ["billing"], "field": "args.purpose"},
            {"template": "sandbox_required", "tools": ["execute_code"]},
            {"template": "max_output_size", "max_chars": 10},
            {"template": "evidence_required", "keys": ["ticket"]},
            {"template": "forbidden_patterns", "patterns": "rm -rf"},
            {
                "id": "raw-post",
                "predicate": "len(str(result)) > 0",
                "phase": "both",
                "capture": ["args.x"],
                "on_pass": "log",
            },
        ],
    }
    rails = compile_policy(doc)
    assert len(rails.rails) == len(TEMPLATES) + 1
    by_template = {r.template: r for r in rails.rails if r.template}
    assert by_template["approval_threshold"].predicate.source == "args.amount == null or args.amount < 5"
    assert (
        by_template["time_window"].predicate.source
        == "time.hour >= 9 and time.hour < 17 and time.weekday in [0, 1]"
    )
    assert (
        by_template["data_residency"].evidence.required == ["region"]
        and by_template["purpose_limitation"].evidence.required == []
    )
    assert by_template["pii_redaction"].on_fail.params == {"kinds": ["email"]}
    assert by_template["sandbox_required"].type.capability.value == "code"
    assert by_template["evidence_required"].predicate.source == "exists(evidence.ticket)"
    raw = rails.by_id("raw-post")
    assert (
        raw.selector.phases == [Phase.PRE, Phase.POST]
        and raw.evidence.capture == ["args.x"]
        and raw.on_pass.action is PolicyAction.LOG
    )


@pytest.mark.parametrize(
    "doc,message",
    [
        ({"version": 2, "requirements": [{"predicate": "true"}]}, "unsupported policy version"),
        ({"version": 1, "requirements": []}, "non-empty list"),
        ({"version": 1, "bogus": 1, "requirements": [{"predicate": "true"}]}, "unknown top-level keys"),
        ({"version": 1, "requirements": [{"template": "nope"}]}, "unknown template"),
        (
            {"version": 1, "requirements": [{"template": "approval_threshold", "tool": "t"}]},
            "requires 'threshold'",
        ),
        ({"version": 1, "requirements": [{"template": "deny_tools"}]}, "requires 'tool'"),
        ({"version": 1, "requirements": [{"id": "x", "predicate": "args.amount >"}]}, "invalid predicate"),
        ({"version": 1, "requirements": [{"id": "x"}]}, "needs a 'predicate'"),
        ({"version": 1, "requirements": [{"id": "x", "predicate": "true", "typo": 1}]}, "unknown keys"),
        (
            {"version": 1, "requirements": [{"id": "x", "predicate": "true", "type": "vibes"}]},
            "unknown risk type",
        ),
        (
            {"version": 1, "requirements": [{"id": "x", "predicate": "true", "capability": "magic"}]},
            "unknown capability",
        ),
        (
            {"version": 1, "requirements": [{"id": "x", "predicate": "true", "on_fail": "explode"}]},
            "invalid action",
        ),
        (
            {"version": 1, "requirements": [{"id": "x", "predicate": "true", "phase": "later"}]},
            "unknown phase",
        ),
        (
            {
                "version": 1,
                "requirements": [{"id": "x", "predicate": "true"}, {"id": "x", "predicate": "true"}],
            },
            "duplicate rail ids",
        ),
        (
            {
                "version": 1,
                "defaults": {"on_fail": "boom"},
                "requirements": [{"id": "x", "predicate": "true"}],
            },
            "invalid defaults",
        ),
        ({"version": 1, "requirements": [{"template": "data_residency"}]}, "allowed_regions"),
        ({"version": 1, "requirements": [{"template": "purpose_limitation"}]}, "allowed_purposes"),
        ({"version": 1, "requirements": [{"template": "evidence_required"}]}, "requires 'keys'"),
        ({"version": 1, "requirements": [{"template": "forbidden_patterns"}]}, "requires 'patterns'"),
        (
            {"version": 1, "requirements": [{"template": "rate_limit", "tools": ["t"], "extra": 1}]},
            "unknown keys",
        ),
    ],
)
def test_compile_errors(doc, message):
    with pytest.raises(PolicyCompileError) as info:
        compile_policy(doc)
    assert message in str(info.value)


def test_load_from_files_and_text(tmp_path):
    yaml_file = tmp_path / "p.yaml"
    yaml_file.write_text("version: 1\nname: f\nrequirements:\n  - id: a\n    predicate: 'true'\n")
    assert compile_policy(yaml_file).name == "f" and compile_policy(str(yaml_file)).name == "f"
    json_file = tmp_path / "p.json"
    json_file.write_text(
        json.dumps({"version": 1, "name": "j", "requirements": [{"id": "a", "predicate": "true"}]})
    )
    assert compile_policy(json_file).name == "j"
    with pytest.raises(PolicyCompileError):
        compile_policy("- not: [a mapping")
    with pytest.raises(PolicyCompileError):
        compile_policy("just a string\n")
