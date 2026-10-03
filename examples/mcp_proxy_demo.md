# Enforcing a policy on any MCP server

```bash
# 1. compile & inspect the policy
typed-rails explain examples/policies/finance.yaml

# 2. run the proxy in front of a real MCP server (here: the reference filesystem server)
typed-rails proxy --policy examples/policies/finance.yaml --evidence evidence.jsonl --agent claude-desktop \
    -- npx -y @modelcontextprotocol/server-filesystem /path/to/data
```

Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "filesystem-governed": {
      "command": "typed-rails",
      "args": ["proxy", "--policy", "/abs/path/policy.yaml", "--evidence", "/abs/path/evidence.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/data"]
    }
  }
}
```

What the proxy does:

| message | behaviour |
|---|---|
| `initialize`, notifications, pings, unknown methods | forwarded verbatim (both directions) |
| `tools/list` | forwarded; tools the agent can never call (static `deny` rails) are removed from the result |
| `tools/call` | evaluated by the policy engine: **deny/quarantine/throttle** → answered by the proxy with a tool error (`isError: true`) explaining which rail blocked it; **require_approval** → approval handler (deny when none); **redact** → forwarded with masked arguments |
| `tools/call` result | post-phase rails: result redaction (`output_pii_redaction`), size limits, custom `phase: post` rules |

Evidence is written for every decision; verify it any time:

```bash
typed-rails evidence evidence.jsonl verify
typed-rails evidence evidence.jsonl show --last 20
typed-rails metrics evidence.jsonl
```

Use `--hmac-key-env RAILS_KEY` to sign records, `--static-evidence '{"region": "EU"}'` to
attach evidence to every call, and pass per-call evidence from the client through the
request's `_meta` object (non-MCP keys are copied into `evidence`).
