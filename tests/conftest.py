from __future__ import annotations

import pytest

from typed_rails import PolicyEngine, compile_policy

FINANCE_POLICY = """
version: 1
name: finance
description: test policy
defaults: {on_fail: deny}
requirements:
  - id: gdpr-anonymised
    title: Anonymised exports
    type: privacy
    tools: [export_report]
    predicate: "evidence.anonymised == true"
    evidence: [anonymised]
    on_fail: {action: redact, fields: [args.customer.email, args.customer.name]}
    citation: "GDPR Art. 5(1)(c)"
  - template: approval_threshold
    id: big-transfers
    tool: transfer_funds
    field: args.amount
    threshold: 1000
  - template: deny_tools
    id: no-drop
    tools: [drop_database]
  - template: rate_limit
    id: search-rate
    tools: [search]
    max_calls: 3
    per_seconds: 60
  - template: trust_gate
    id: code-trust
    tools: [execute_code]
    min_trust: 0.7
  - template: pii_redaction
    id: echo-pii
    tools: [echo]
  - template: output_pii_redaction
    id: lookup-output
    tools: [lookup]
  - template: forbidden_patterns
    id: no-sql-injection
    tools: [query]
    field: args.sql
    patterns: ["(?i)drop\\\\s+table", "(?i);\\\\s*delete"]
  - template: allowed_tools
    id: junior-tools
    agents: [junior]
    tools: [search, echo]
"""


@pytest.fixture
def rails():
    return compile_policy(FINANCE_POLICY)


@pytest.fixture
def engine(rails):
    return PolicyEngine(rails)
