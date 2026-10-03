from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from typed_rails import EvidenceStore, PolicyEngine, compile_policy
from typed_rails.mcp_proxy import MCPMessageInterceptor

HERE = Path(__file__).parent
POLICY = """
version: 1
name: proxy-test
requirements:
  - template: deny_tools
    id: no-drop
    tools: [drop_database]
  - template: approval_threshold
    id: big-transfers
    tool: transfer_funds
    field: args.amount
    threshold: 1000
  - template: pii_redaction
    id: echo-pii
    tools: [echo]
  - template: output_pii_redaction
    id: lookup-output
    tools: [lookup]
"""


def test_interceptor_logic():
    engine = PolicyEngine(compile_policy(POLICY))
    seen = []
    icp = MCPMessageInterceptor(engine, agent="tester", log=seen.append)
    fwd, reply = icp.on_client_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
    )
    assert fwd is not None and reply is None and icp.protocol_version == "2025-06-18"
    fwd, reply = icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "drop_database", "arguments": {}},
        }
    )
    assert (
        fwd is None
        and reply["result"]["isError"]
        and "no-drop" in reply["result"]["content"][0]["text"]
        and "resultType" not in reply["result"]
    )
    fwd, reply = icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "transfer_funds", "arguments": {"amount": 5000}},
        }
    )
    assert fwd is None and "approval" in reply["result"]["content"][0]["text"]
    fwd, reply = icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "hi a@b.com"}},
        }
    )
    assert (
        reply is None
        and fwd["params"]["arguments"] == {"text": "hi [REDACTED:email]"}
        and 4 in icp.pending_calls
    )
    out = icp.on_server_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "result": {"content": [{"type": "text", "text": "echo: hi [REDACTED:email]"}], "isError": False},
        }
    )
    assert out["result"]["content"][0]["text"].startswith("echo:") and 4 not in icp.pending_calls
    icp.on_client_message({"jsonrpc": "2.0", "id": 5, "method": "tools/list"})
    listed = icp.on_server_message(
        {"jsonrpc": "2.0", "id": 5, "result": {"tools": [{"name": "add"}, {"name": "drop_database"}]}}
    )
    assert [t["name"] for t in listed["result"]["tools"]] == ["add"] and icp.stats.hidden_tools == [
        "drop_database"
    ]
    icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"name": "jane"}},
        }
    )
    post = icp.on_server_message(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "result": {"content": [{"type": "text", "text": "jane@example.com"}], "isError": False},
        }
    )
    assert post["result"]["content"][0]["text"] == "[REDACTED:email]"
    # new protocol revision -> resultType on proxy-generated results, _meta evidence forwarded
    icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "drop_database",
                "arguments": {},
                "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "ticket": "T1"},
            },
        }
    )
    _, reply = icp.on_client_message(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "drop_database", "arguments": {}},
        }
    )
    assert reply["result"]["resultType"] == "complete"
    assert icp.stats.tool_calls == 6 and icp.stats.denied == 4 and icp.stats.redacted == 2
    assert any("denied" in s for s in seen)
    # notifications and unknown methods pass through
    assert icp.on_client_message({"jsonrpc": "2.0", "method": "notifications/initialized"})[0] is not None
    assert (
        icp.on_server_message({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})["method"]
        == "notifications/tools/list_changed"
    )


def test_proxy_end_to_end(tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY)
    evidence = tmp_path / "evidence.jsonl"
    cmd = [
        sys.executable,
        "-m",
        "typed_rails.cli",
        "proxy",
        "--policy",
        str(policy),
        "--evidence",
        str(evidence),
        "--agent",
        "tester",
        "--",
        sys.executable,
        str(HERE / "fake_mcp_server.py"),
    ]
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    assert proc.stdin is not None and proc.stdout is not None

    def rpc(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        assert line, "proxy closed unexpectedly"
        return json.loads(line)

    init = rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
        }
    )
    assert init["result"]["serverInfo"]["name"] == "fake"
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()
    listed = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert "drop_database" not in [t["name"] for t in listed["result"]["tools"]]
    added = rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "add", "arguments": {"a": 1, "b": 2}},
        }
    )
    assert added["result"]["content"][0]["text"] == "3" and added["result"]["structuredContent"] == {"sum": 3}
    denied = rpc(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "drop_database", "arguments": {}},
        }
    )
    assert denied["result"]["isError"] is True and "typed-rails" in denied["result"]["content"][0]["text"]
    echoed = rpc(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"text": "reach me at jane@example.com"}},
        }
    )
    assert echoed["result"]["content"][0]["text"] == "echo: reach me at [REDACTED:email]"
    approval = rpc(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "transfer_funds", "arguments": {"amount": 9999}},
        }
    )
    assert approval["result"]["isError"] is True and "approval" in approval["result"]["content"][0]["text"]
    small = rpc(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "transfer_funds", "arguments": {"amount": 10}},
        }
    )
    assert small["result"]["content"][0]["text"] == "transferred 10"
    looked = rpc(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "lookup", "arguments": {"name": "jane"}},
        }
    )
    assert (
        "[REDACTED:email]" in looked["result"]["content"][0]["text"]
        and "[REDACTED:phone]" in looked["result"]["content"][0]["text"]
    )
    pong = rpc({"jsonrpc": "2.0", "id": 9, "method": "ping"})
    assert pong["result"] == {}
    _out, err = proc.communicate(timeout=30)  # closes stdin -> proxy and server exit
    assert proc.returncode == 0, err
    assert "denied drop_database" in err and "hid tools: drop_database" in err
    store = EvidenceStore.load(evidence)
    assert store.verify().ok
    kinds = [(r.tool, r.phase, r.action) for r in store.records() if r.kind == "decision"]
    assert (
        ("drop_database", "pre", "deny") in kinds
        and ("echo", "pre", "redact") in kinds
        and ("lookup", "post", "redact") in kinds
    )


def test_proxy_terminates_a_server_that_ignores_stdin(rails):
    """After the client disconnects, a server that never exits is terminated after the grace period."""
    import io
    import time

    from typed_rails.mcp_proxy import run_proxy

    engine = PolicyEngine(rails)
    started = time.monotonic()
    code = run_proxy(
        engine,
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=io.BytesIO(b""),
        stdout=io.BytesIO(),
        log_stream=io.StringIO(),
        exit_grace_s=0.5,
    )
    assert code != 0 and time.monotonic() - started < 20
