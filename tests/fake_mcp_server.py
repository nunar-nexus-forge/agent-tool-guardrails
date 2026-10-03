"""A minimal MCP stdio server used by the proxy tests (initialize, tools/list, tools/call, ping)."""

from __future__ import annotations

import json
import sys

TOOLS = [
    {
        "name": "add",
        "description": "Add two numbers",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
            "required": ["a", "b"],
        },
    },
    {
        "name": "transfer_funds",
        "description": "Move money",
        "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}},
    },
    {
        "name": "echo",
        "description": "Echo the text",
        "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
    },
    {
        "name": "lookup",
        "description": "Look up a contact",
        "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
    },
    {
        "name": "drop_database",
        "description": "Destroy everything",
        "inputSchema": {"type": "object", "additionalProperties": False},
    },
]


def respond(msg_id, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


def error(msg_id, code, message):
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}) + "\n"
    )
    sys.stdout.flush()


def call(name, args):
    if name == "add":
        return {
            "content": [{"type": "text", "text": str(args["a"] + args["b"])}],
            "structuredContent": {"sum": args["a"] + args["b"]},
            "isError": False,
        }
    if name == "transfer_funds":
        return {"content": [{"type": "text", "text": f"transferred {args.get('amount')}"}], "isError": False}
    if name == "echo":
        return {"content": [{"type": "text", "text": f"echo: {args.get('text')}"}], "isError": False}
    if name == "lookup":
        return {
            "content": [{"type": "text", "text": "Jane Doe <jane@example.com> 555-123-4567"}],
            "isError": False,
        }
    if name == "drop_database":
        return {"content": [{"type": "text", "text": "dropped"}], "isError": False}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            respond(
                msg_id,
                {
                    "protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake", "version": "0"},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "ping":
            respond(msg_id, {})
        elif method == "tools/list":
            respond(msg_id, {"tools": TOOLS})
        elif method == "tools/call":
            result = call(msg["params"]["name"], msg["params"].get("arguments") or {})
            if result is None:
                error(msg_id, -32602, f"Unknown tool: {msg['params']['name']}")
            else:
                respond(msg_id, result)
        elif msg_id is not None:
            error(msg_id, -32601, "Method not found")


if __name__ == "__main__":
    main()
