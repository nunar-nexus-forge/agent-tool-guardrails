# Changelog

All notable changes to `agent-tool-guardrails` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-03

First release on PyPI: the initial version of 27 September 2026 (*Added*) together with
the changes made to it before publishing.

### Added
- Typed Rails data model: `RailType` (risk × capability), `Predicate`, `EvidenceSpec`, `ActionSpec`, selectors with pre/post phases, `CallContext`, `Decision`.
- Safe predicate expression language (parser + evaluator, no `eval`), PII detection and field redaction.
- Policy compiler: YAML/JSON requirements and 14 templates (`allowed_tools`, `deny_tools`, `approval_threshold`, `rate_limit`, `trust_gate`, `pii_redaction`, `output_pii_redaction`, `time_window`, `data_residency`, `purpose_limitation`, `sandbox_required`, `max_output_size`, `evidence_required`, `forbidden_patterns`) compiled into a content-addressed `RailSet`.
- Policy engine with action combination, redaction, rate limiting, approvals, fail-closed predicate errors, static tool denial analysis and a `guard` decorator (sync + async).
- Tamper-evident Evidence Store (hash chain, HMAC signatures, Merkle root, JSONL persistence) and governance metrics.
- Trust-scored governance loop (compliance scores, trust evolution, pairwise trust and privilege weights, fusion thresholds, policy adaptation) and policy-driven memory sharding.
- MCP stdio proxy enforcing rails on `tools/call` (denials as tool errors, in-flight redaction of arguments and results, hidden denied tools, protocol-revision aware).
- The `typed-rails` CLI (`compile`, `explain`, `check`, `proxy`, `evidence`, `metrics`) and a LangChain tool guard.

### Changed
- README, `NOTICE`, `CITATION.cff` and the package metadata now describe the software only.
- `PolicyEngine.guard` and the MCP proxy stamp each `CallContext` with the engine clock
  (new `PolicyEngine.now()`), so `time.*` predicates can be pinned in tests and demos. The
  default clock is still `time.time`.

### Fixed
- The MCP proxy terminated the server as soon as the client disconnected, before the server could
  exit on its own; on Windows the terminated server reports exit code 1, which became the proxy's exit
  code after a clean session. The proxy now waits for the server (`exit_grace_s`, default 5 s) and only
  then terminates it.
- CI caches uv by `pyproject.toml` (the lock file is not committed), which newer `setup-uv` releases require.
- Approving a `require_approval` decision (`PolicyEngine.approve`, an approval handler or the MCP
  proxy) appended the approval note to a `reasons` list that the decision's evidence record still
  referenced, so `EvidenceStore.verify()` reported that record as tampered. Evidence records now
  deep-copy every field they store.
- `examples/guard_demo.py` produced different output depending on the weekday and time of day
  (business-hours rail) and appended to a previous evidence log on every run; it now pins the
  clock and starts from a fresh log.
