from __future__ import annotations

import json

from typed_rails.cli import main

POLICY = """
version: 1
name: cli
requirements:
  - template: deny_tools
    id: no-drop
    tools: [drop_database]
  - template: pii_redaction
    id: pii
    tools: [echo]
  - template: output_pii_redaction
    id: out
    tools: [lookup]
"""


def test_compile_explain_check(tmp_path, capsys):
    policy = tmp_path / "p.yaml"
    policy.write_text(POLICY)
    compiled = tmp_path / "p.rails.json"
    assert main(["compile", str(policy), "-o", str(compiled)]) == 0
    assert json.loads(compiled.read_text())["name"] == "cli"
    assert main(["compile", str(policy)]) == 0
    assert json.loads(capsys.readouterr().out)["rails"][0]["id"] == "no-drop"
    assert main(["explain", str(compiled)]) == 0
    assert "| no-drop |" in capsys.readouterr().out
    assert main(["check", str(policy), "--tool", "drop_database"]) == 1
    assert "DENY" in capsys.readouterr().out
    assert main(["check", str(policy), "--tool", "echo", "--args", '{"text": "a@b.com"}']) == 0
    out = capsys.readouterr().out
    assert "REDACT" in out and "[REDACTED:email]" in out
    assert (
        main(
            ["check", str(policy), "--tool", "lookup", "--args", "{}", "--result", '"555-123-4567"', "--json"]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["pre"]["allowed"] and data["post"]["redactions"] == ["result"]
    assert main(["check", str(policy), "--tool", "lookup", "--result", '"ok"']) == 0
    capsys.readouterr()
    assert main(["check", str(policy), "--tool", "x", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["allowed"] is True


def test_evidence_and_metrics_commands(tmp_path, capsys, monkeypatch):
    from typed_rails import CallContext, EvidenceStore, PolicyEngine, compile_policy

    store_path = tmp_path / "e.jsonl"
    monkeypatch.setenv("RAILS_KEY", "k")
    engine = PolicyEngine(compile_policy(POLICY), evidence=EvidenceStore(store_path, hmac_key="k"))
    engine.evaluate(CallContext(tool="drop_database", agent="a"))
    engine.evaluate(CallContext(tool="echo", args={"text": "hi"}, agent="a"))
    assert main(["evidence", str(store_path), "--hmac-key-env", "RAILS_KEY", "verify"]) == 0
    assert "OK: 2 record" in capsys.readouterr().out
    assert main(["evidence", str(store_path), "show", "--last", "1"]) == 0
    assert "echo" in capsys.readouterr().out
    assert main(["evidence", str(store_path), "show", "--json"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2
    assert main(["evidence", str(store_path), "export", str(tmp_path / "copy.jsonl")]) == 0
    assert main(["metrics", str(store_path)]) == 0
    assert "safety incident rate" in capsys.readouterr().out
    assert main(["metrics", str(store_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["decisions"] == 2
    store_path.write_text(store_path.read_text().replace('"allowed": false', '"allowed": true', 1))
    assert main(["evidence", str(store_path), "verify"]) == 1


def test_errors(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrequirements:\n  - template: nope\n")
    assert main(["compile", str(bad)]) == 2
    assert "policy error" in capsys.readouterr().err
    assert main(["evidence", str(tmp_path / "missing.jsonl"), "verify"]) == 0  # empty store verifies
    assert main(["compile", str(tmp_path / "missing.yaml")]) == 2
