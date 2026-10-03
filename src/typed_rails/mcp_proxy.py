# SPDX-License-Identifier: Apache-2.0
"""An MCP (Model Context Protocol) stdio proxy that enforces Typed Rails on every ``tools/call``.

The proxy sits between an MCP client (Claude Desktop, Cursor, an agent framework) and an
MCP server launched as a subprocess. It speaks newline-delimited JSON-RPC on both sides and
forwards everything verbatim - except:

* ``tools/call`` requests are evaluated by the :class:`~typed_rails.engine.PolicyEngine`.
  Denied calls are answered *by the proxy* with a tool-execution error (``isError: true``)
  so the model can self-correct; redacted calls are forwarded with masked arguments;
  approval-required calls go through the engine's approval handler (deny when none is set).
* ``tools/call`` results are post-evaluated (result redaction, output rails).
* ``tools/list`` results optionally omit tools the agent can never call.

Zero code changes on either side: point your client at ``typed-rails proxy --policy p.yaml
-- <original server command>``. The proxy never writes anything but MCP messages to stdout;
its own logs go to stderr.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TextIO

from .engine import PolicyEngine
from .model import CallContext, Decision, PolicyAction

NEW_PROTOCOL_MIN = "2026-07-28"  # revision that introduced ``resultType`` in results


@dataclass
class ProxyStats:
    requests: int = 0
    tool_calls: int = 0
    allowed: int = 0
    denied: int = 0
    redacted: int = 0
    approvals: int = 0
    hidden_tools: list[str] = field(default_factory=list)


class MCPMessageInterceptor:
    """Transport-independent logic: decide what to do with each JSON-RPC message.

    Kept separate from the asyncio plumbing so it can be unit-tested directly.
    """

    def __init__(
        self,
        engine: PolicyEngine,
        *,
        agent: str = "mcp-client",
        static_evidence: Mapping[str, Any] | None = None,
        hide_denied_tools: bool = True,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.engine = engine
        self.agent = agent
        self.static_evidence = dict(static_evidence or {})
        self.hide_denied_tools = hide_denied_tools
        self.log = log or (lambda msg: None)
        self.protocol_version: str | None = None
        self.pending_calls: dict[Any, tuple[CallContext, Decision]] = {}
        self.pending_lists: set[Any] = set()
        self.stats = ProxyStats()

    # -- helpers ------------------------------------------------------------------

    def _result_envelope(self, result: dict[str, Any]) -> dict[str, Any]:
        if self.protocol_version and self.protocol_version >= NEW_PROTOCOL_MIN:
            return {"resultType": "complete", **result}
        return result

    def _tool_error(self, msg_id: Any, text: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": self._result_envelope({"content": [{"type": "text", "text": text}], "isError": True}),
        }

    @staticmethod
    def _denial_text(decision: Decision) -> str:
        rails = ", ".join(e.rail_id for e in decision.failed_rails) or decision.action.value
        reasons = "; ".join(decision.reasons) or decision.action.value
        if decision.action == PolicyAction.REQUIRE_APPROVAL:
            return f"Blocked by typed-rails policy ({rails}): human approval is required. {reasons}"
        if decision.action == PolicyAction.THROTTLE:
            retry = f" Retry after {decision.retry_after_s:g}s." if decision.retry_after_s else ""
            return f"Blocked by typed-rails policy ({rails}): rate limited.{retry} {reasons}"
        return f"Blocked by typed-rails policy ({rails}): {reasons}"

    # -- client -> server ----------------------------------------------------------

    def on_client_message(self, msg: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Return ``(forward_to_server, reply_to_client)``; either may be ``None``."""
        method = msg.get("method")
        msg_id = msg.get("id")
        if method is not None:
            self.stats.requests += 1
        meta = msg.get("params", {}).get("_meta", {}) if isinstance(msg.get("params"), dict) else {}
        pv = meta.get("io.modelcontextprotocol/protocolVersion")
        if pv:
            self.protocol_version = str(pv)
        if method == "initialize":
            params = msg.get("params") or {}
            if params.get("protocolVersion"):
                self.protocol_version = str(params["protocolVersion"])
            return msg, None
        if method == "tools/list" and msg_id is not None:
            self.pending_lists.add(msg_id)
            return msg, None
        if method == "tools/call" and msg_id is not None:
            params = msg.get("params") or {}
            tool = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            evidence = dict(self.static_evidence)
            for k, v in meta.items():
                if not k.startswith("io.modelcontextprotocol/"):
                    evidence[k] = v
            ctx = CallContext(
                tool=tool,
                args=dict(arguments) if isinstance(arguments, dict) else {"input": arguments},
                agent=self.agent,
                evidence=evidence,
                call_id=str(msg_id),
                timestamp=self.engine.now(),
            )
            decision = self.engine.evaluate(ctx)
            self.stats.tool_calls += 1
            if decision.approval_required:
                if self.engine.request_approval(ctx, decision):
                    self.stats.approvals += 1
                else:
                    self.stats.denied += 1
                    self.log(f"denied {tool}: approval required")
                    return None, self._tool_error(msg_id, self._denial_text(decision))
            if not decision.allowed:
                self.stats.denied += 1
                self.log(f"denied {tool}: {'; '.join(decision.reasons)}")
                return None, self._tool_error(msg_id, self._denial_text(decision))
            self.stats.allowed += 1
            forward = msg
            if decision.redactions:
                self.stats.redacted += 1
                forward = dict(msg)
                forward["params"] = {**params, "arguments": decision.args}
                self.log(f"redacted {tool}: {', '.join(decision.redactions)}")
            self.pending_calls[msg_id] = (ctx, decision)
            return forward, None
        return msg, None

    # -- server -> client ----------------------------------------------------------

    def on_server_message(self, msg: dict[str, Any]) -> dict[str, Any]:
        msg_id = msg.get("id")
        if msg_id is None or "result" not in msg:
            return msg
        result = msg["result"]
        if msg_id in self.pending_lists and isinstance(result, dict):
            self.pending_lists.discard(msg_id)
            if isinstance(result.get("protocolVersion"), str):
                self.protocol_version = result["protocolVersion"]
            tools = result.get("tools")
            if self.hide_denied_tools and isinstance(tools, list):
                names: list[str] = [str(t["name"]) for t in tools if isinstance(t, dict) and t.get("name")]
                hidden = set(self.engine.statically_denied_tools(names, self.agent))
                if hidden:
                    self.stats.hidden_tools = sorted(set(self.stats.hidden_tools) | hidden)
                    msg = dict(msg)
                    msg["result"] = {
                        **result,
                        "tools": [t for t in tools if not (isinstance(t, dict) and t.get("name") in hidden)],
                    }
                    self.log(f"hid tools: {', '.join(sorted(hidden))}")
            return msg
        if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
            self.protocol_version = result["protocolVersion"]
        pending = self.pending_calls.pop(msg_id, None)
        if pending is None or not isinstance(result, dict):
            return msg
        ctx, _pre = pending
        text_parts = [
            c.get("text", "")
            for c in result.get("content", [])
            if isinstance(c, dict) and c.get("type") == "text"
        ]
        post_result: Any = result.get("structuredContent", "\n".join(text_parts) if text_parts else result)
        post = self.engine.evaluate_result(ctx, post_result)
        if not post.allowed:
            self.stats.denied += 1
            self.log(f"result rejected for {ctx.tool}: {'; '.join(post.reasons)}")
            return self._tool_error(msg_id, self._denial_text(post))
        if post.redactions:
            self.stats.redacted += 1
            new_result = dict(result)
            if "structuredContent" in result and not isinstance(post.result, str):
                new_result["structuredContent"] = post.result
                new_result["content"] = [{"type": "text", "text": json.dumps(post.result, default=str)}]
            else:
                new_result["content"] = [{"type": "text", "text": str(post.result)}] + [
                    c
                    for c in result.get("content", [])
                    if not (isinstance(c, dict) and c.get("type") == "text")
                ]
            msg = dict(msg)
            msg["result"] = new_result
        return msg


class MCPProxy:
    def __init__(
        self,
        engine: PolicyEngine,
        server_command: list[str],
        *,
        agent: str = "mcp-client",
        static_evidence: Mapping[str, Any] | None = None,
        hide_denied_tools: bool = True,
        stdin: Any = None,
        stdout: Any = None,
        log_stream: TextIO | None = None,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> None:
        self.server_command = list(server_command)
        self._stdin = stdin
        self._stdout = stdout
        self._log_stream = log_stream if log_stream is not None else sys.stderr
        self.env = dict(env) if env is not None else None
        self.cwd = cwd
        self.interceptor = MCPMessageInterceptor(
            engine,
            agent=agent,
            static_evidence=static_evidence,
            hide_denied_tools=hide_denied_tools,
            log=self.log,
        )
        self.process: asyncio.subprocess.Process | None = None

    def log(self, message: str) -> None:
        print(f"[typed-rails] {message}", file=self._log_stream, flush=True)

    def _write_client(self, msg: dict[str, Any]) -> None:
        out = self._stdout if self._stdout is not None else sys.stdout.buffer
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        out.write(data)
        out.flush()

    async def _pump_client(self) -> None:
        assert self.process is not None and self.process.stdin is not None
        loop = asyncio.get_running_loop()
        reader = self._stdin if self._stdin is not None else sys.stdin.buffer
        while True:
            line = await loop.run_in_executor(None, reader.readline)
            if not line:
                break
            text = line.decode("utf-8").strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                self.log("dropping malformed client message")
                continue
            for msg in parsed if isinstance(parsed, list) else [parsed]:
                if not isinstance(msg, dict):
                    continue
                forward, reply = self.interceptor.on_client_message(msg)
                if reply is not None:
                    self._write_client(reply)
                if forward is not None:
                    self.process.stdin.write(
                        (json.dumps(forward, separators=(",", ":")) + "\n").encode("utf-8")
                    )
                    await self.process.stdin.drain()
        with _suppress():
            self.process.stdin.close()

    async def _pump_server(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8").strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                self.log("dropping malformed server message")
                continue
            for msg in parsed if isinstance(parsed, list) else [parsed]:
                if isinstance(msg, dict):
                    self._write_client(self.interceptor.on_server_message(msg))

    async def run(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            *self.server_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
            env=self.env,
            cwd=self.cwd,
        )
        self.log(f"proxying {' '.join(self.server_command)} (policy {self.interceptor.engine.rails.name!r})")
        client_task = asyncio.create_task(self._pump_client())
        server_task = asyncio.create_task(self._pump_server())
        done, pending = await asyncio.wait({client_task, server_task}, return_when=asyncio.FIRST_COMPLETED)
        if client_task in done:
            with _suppress():
                await asyncio.wait_for(server_task, timeout=5.0)
        for task in pending:
            task.cancel()
        if self.process.returncode is None:
            with _suppress():
                self.process.terminate()
                await asyncio.wait_for(self.process.wait(), timeout=5.0)
        s = self.interceptor.stats
        self.log(
            f"done: {s.tool_calls} tool call(s), {s.allowed} allowed, "
            f"{s.denied} denied, {s.redacted} redacted"
        )
        return self.process.returncode or 0


class _suppress:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: Any) -> bool:
        return True


def run_proxy(engine: PolicyEngine, server_command: list[str], **kwargs: Any) -> int:
    return asyncio.run(MCPProxy(engine, server_command, **kwargs).run())
