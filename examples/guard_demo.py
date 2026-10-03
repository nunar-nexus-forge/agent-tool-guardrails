# SPDX-License-Identifier: Apache-2.0
"""In-process enforcement: compile the finance policy, guard some tools, print the evidence.

    python examples/guard_demo.py

The output is reproducible: the evidence log is recreated on every run, and the engine clock is
pinned to a weekday morning because the finance policy contains a business-hours rail
(``business-hours-transfers``: weekdays 07:00-20:00 UTC). Remove ``clock=`` below to evaluate
the rails against the real time.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from typed_rails import (
    ApprovalRequired,
    CallContext,
    EvidenceStore,
    PolicyDenied,
    PolicyEngine,
    compile_policy,
)

HERE = Path(__file__).parent
EVIDENCE = HERE / "evidence.jsonl"
if EVIDENCE.exists():
    EVIDENCE.unlink()  # start from an empty, freshly signed evidence log
DEMO_TIME = datetime(2026, 9, 29, 10, 0, tzinfo=timezone.utc).timestamp()  # a Tuesday, 10:00 UTC

rails = compile_policy(HERE / "policies" / "finance.yaml")
store = EvidenceStore(EVIDENCE, hmac_key=os.environ.get("RAILS_KEY", "demo-key"))
engine = PolicyEngine(
    rails,
    evidence=store,
    approval_handler=lambda ctx, d: ctx.args.get("amount", 0) < 5000,
    clock=lambda: DEMO_TIME,
)


@engine.guard("transfer_funds", agent="treasury-bot")
def transfer_funds(amount: float, to: str) -> str:
    return f"transferred {amount} to {to}"


@engine.guard("lookup_customer", agent="support-bot")
def lookup_customer(customer_id: str) -> str:
    return f"customer {customer_id}: Jane Doe <jane@example.com> +1 555 123 4567"


@engine.guard("drop_database", agent="treasury-bot")
def drop_database() -> str:
    return "dropped"


def show(label, fn, *args, **kwargs):
    try:
        print(f"{label:<38} -> {fn(*args, **kwargs)}")
    except ApprovalRequired as e:
        print(f"{label:<38} -> APPROVAL REQUIRED: {e}")
    except PolicyDenied as e:
        print(f"{label:<38} -> DENIED: {e}")


print(rails.explain(), "\n")
show("transfer 50 to ACME", transfer_funds, 50, to="ACME")
show("transfer 2500 to ACME (handler approves)", transfer_funds, 2500, to="ACME")
show("transfer 9000 to ACME (handler rejects)", transfer_funds, 9000, to="ACME")
show("lookup customer 42 (result redacted)", lookup_customer, "42")
show("drop database", drop_database)

decision = engine.evaluate(
    CallContext(
        tool="export_report", args={"customer": {"email": "a@b.com", "name": "Jane"}}, agent="analyst"
    )
)
print("\n" + decision.explain())
print("args after redaction:", decision.args)

print("\nevidence:", store.verify(), "| merkle root", store.merkle_root()[:16], "…")
print(engine.metrics().to_markdown())
