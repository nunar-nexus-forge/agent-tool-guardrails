# Policy documents

```yaml
version: 1                      # schema version (required: 1)
name: finance                   # policy name (recorded in evidence)
description: optional text
defaults:                       # optional
  on_fail: deny                 # default action when a predicate fails (allow|log|redact|throttle|require_approval|quarantine|deny)
  on_pass: allow
  type: compliance              # default risk type
  capability: tool              # default capability type
  agents: ["*"]                 # default agent selector
metadata: {}                    # free-form, carried into the compiled RailSet
requirements: [...]             # non-empty list of raw rules and/or template instances
```

## Raw rule

| key | meaning |
|---|---|
| `id` | rail id (default `rule-<index>`); must be unique |
| `title`, `description`, `citation`, `tags`, `priority` | documentation and ordering (higher priority evaluates first) |
| `type` / `risk` | `safety`, `privacy`, `compliance`, `security`, `cost`, `quality` |
| `capability` | `tool`, `api`, `memory`, `data`, `message`, `code` |
| `tools`, `agents` (or `applies_to: {tools, agents}`) | glob selectors (`fnmatch`), default `*` |
| `phase` | `pre` (default), `post`, or `both` |
| `predicate` | expression that must be true (see below) |
| `evidence` | list of required evidence keys, or `{required: [...], capture: [...]}` |
| `capture` | extra namespace paths to snapshot into the evidence record |
| `on_fail`, `on_pass` | action name or `{action, fields, message, retry_after_s, detect_pii, ...}` |

## Templates

| template | keys | compiles to |
|---|---|---|
| `allowed_tools` | `agents`, `tools` | `tool in [...]` on every tool for those agents → deny |
| `deny_tools` | `tools` | `false` on those tools → deny |
| `approval_threshold` | `tool`, `field` (default `args.amount`), `threshold`, `inclusive` | `field == null or field <= threshold` → require_approval |
| `rate_limit` | `tools`, `max_calls`, `per_seconds` | `rate(tool, per) < max` → throttle (with retry-after) |
| `trust_gate` | `tools`, `min_trust` | `agent.trust >= min` → deny |
| `pii_redaction` | `tools`, `fields`, `kinds` | `count_pii(args) == 0` → redact (fields and/or detected PII) |
| `output_pii_redaction` | `tools` | post phase `count_pii(result) == 0` → redact result |
| `time_window` | `tools`, `hours: [start, end]`, `weekdays` | UTC hour/weekday check → deny |
| `data_residency` | `tools`, `allowed_regions`, `field` (default `evidence.region`) | `field in [...]` → deny; evidence required |
| `purpose_limitation` | `tools`, `allowed_purposes`, `field` (default `evidence.purpose`) | `field in [...]` → deny; evidence required |
| `sandbox_required` | `tools`, `field` (default `evidence.sandbox`) | `field == true` → deny (capability `code`) |
| `max_output_size` | `tools`, `max_chars` | post phase `len(str(result)) <= n` → deny |
| `evidence_required` | `tools`, `keys` | `exists(evidence.k) and ...` → deny |
| `forbidden_patterns` | `tools`, `field` (default `args`), `patterns` | `not matches(field, p) and ...` → deny |

Any template accepts the raw-rule documentation keys (`id`, `title`, `citation`, `tags`,
`priority`, `phase`, `agents`, `on_fail`, `on_pass`, `type`, `capability`, `evidence`).

## Predicate namespace

| path | content |
|---|---|
| `tool` | tool name |
| `capability` | capability type of the call |
| `args.*` | tool arguments (nested paths, list indices `args.items[0]`) |
| `agent.name`, `agent.trust`, `agent.role` | the calling agent; trust comes from the context, `trust_fn`, or the governance loop |
| `evidence.*` | evidence attached to the call (static evidence + per-call evidence + MCP `_meta`) |
| `session.*`, `env.*` | caller-provided context; `env.strictness` is the governance knob |
| `time.epoch`, `time.hour`, `time.minute`, `time.weekday`, `time.iso` | evaluation time (UTC) |
| `result` | the tool result (post phase only) |
| `phase`, `call_id` | `pre`/`post`, call identifier |

Missing paths evaluate to `null`; comparisons with `null` are false (except `==`/`!=`).

## Actions and combination

`allow < log < redact < throttle < require_approval < quarantine < deny` - the most severe
action of all applicable rails wins. `redact` keeps the call allowed but masks the named
fields (`args.customer.email`, `args.*`, `**`, or `result...`) and, unless `detect_pii:
false`, every detected PII match. `throttle` blocks the call with `retry_after_s`.
`require_approval` blocks unless the engine's approval handler (or `engine.approve`)
records an approval. Predicate errors fail closed (`EngineConfig(fail_closed=False)` to
change).
