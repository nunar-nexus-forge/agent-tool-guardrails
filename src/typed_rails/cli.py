# SPDX-License-Identifier: Apache-2.0
"""``typed-rails`` command line interface (distribution ``agent-tool-guardrails``)."""

from __future__ import annotations

import argparse
import json
import os
import sys

from ._version import __version__
from .compiler import PolicyCompileError, RailSet, compile_policy
from .engine import PolicyEngine
from .evidence import EvidenceStore
from .metrics import compute_metrics
from .model import CallContext


def _load_rails(path: str) -> RailSet:
    if path.endswith(".rails.json") or path.endswith(".compiled.json"):
        return RailSet.load(path)
    return compile_policy(path)


def cmd_compile(args: argparse.Namespace) -> int:
    rails = compile_policy(args.policy)
    if args.out:
        rails.save(args.out)
        print(
            f"compiled {len(rails.rails)} rail(s) -> {args.out}  policy_hash={rails.policy_hash[:16]}…",
            file=sys.stderr,
        )
    else:
        print(json.dumps(rails.to_dict(), indent=2, default=str))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    print(_load_rails(args.policy).explain())
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    rails = _load_rails(args.policy)
    engine = PolicyEngine(rails)
    ctx = CallContext(
        tool=args.tool,
        args=json.loads(args.args) if args.args else {},
        agent=args.agent,
        agent_trust=args.trust,
        evidence=json.loads(args.evidence) if args.evidence else {},
    )
    decision = engine.evaluate(ctx)
    if args.result is not None:
        post = engine.evaluate_result(ctx, json.loads(args.result))
        if args.json:
            print(json.dumps({"pre": decision.to_dict(), "post": post.to_dict()}, indent=2, default=str))
        else:
            print(decision.explain())
            print(post.explain())
        return 0 if (decision.allowed and post.allowed) else 1
    if args.json:
        print(json.dumps(decision.to_dict(), indent=2, default=str))
    else:
        print(decision.explain())
        if decision.redactions:
            print(f"  args after redaction: {json.dumps(decision.args, default=str)}")
    return 0 if decision.allowed else 1


def cmd_proxy(args: argparse.Namespace) -> int:
    from .mcp_proxy import run_proxy

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("proxy: give the MCP server command after '--'")
    rails = _load_rails(args.policy)
    key = os.environ.get(args.hmac_key_env) if args.hmac_key_env else None
    store = EvidenceStore(args.evidence, hmac_key=key) if args.evidence else EvidenceStore()
    engine = PolicyEngine(rails, evidence=store)
    static = json.loads(args.static_evidence) if args.static_evidence else None
    return run_proxy(
        engine, command, agent=args.agent, static_evidence=static, hide_denied_tools=not args.no_hide
    )


def cmd_evidence(args: argparse.Namespace) -> int:
    key = os.environ.get(args.hmac_key_env) if args.hmac_key_env else None
    store = EvidenceStore.load(args.file, hmac_key=key)
    if args.evidence_command == "verify":
        result = store.verify()
        print(str(result))
        print(f"merkle root: {store.merkle_root()}")
        return 0 if result.ok else 1
    if args.evidence_command == "show":
        records = store.records()[-args.last :] if args.last else store.records()
        for r in records:
            if args.json:
                print(json.dumps(r.to_dict(), default=str))
            else:
                rails = ",".join(f"{e['rail_id']}{'' if e['passed'] else '!'}" for e in r.rails)
                redacted = ("redacted=" + ",".join(r.redactions)) if r.redactions else ""
                print(
                    f"#{r.index:<4} {r.kind:<9} {r.agent or '-':<14} {r.tool or '-':<22} "
                    f"{r.phase or '-':<4} {r.action or '-':<16} rails=[{rails}] {redacted}"
                )
        return 0
    if args.evidence_command == "export":
        store.export(args.out)
        print(f"exported {len(store)} record(s) -> {args.out}", file=sys.stderr)
        return 0
    raise SystemExit("unknown evidence command")


def cmd_metrics(args: argparse.Namespace) -> int:
    store = EvidenceStore.load(args.file)
    m = compute_metrics(store.records())
    if args.json:
        print(json.dumps(m.to_dict(), indent=2))
    else:
        print(m.to_markdown())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="typed-rails", description="Typed policy rails for agent-tool calls.")
    p.add_argument("--version", action="version", version=f"typed-rails {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("compile", help="compile a policy document into executable rails")
    s.add_argument("policy", help="policy .yaml/.json")
    s.add_argument("-o", "--out", help="write the compiled rails (JSON) here")
    s.set_defaults(func=cmd_compile)

    s = sub.add_parser("explain", help="render the rails of a policy as a Markdown table")
    s.add_argument("policy")
    s.set_defaults(func=cmd_explain)

    s = sub.add_parser("check", help="evaluate one hypothetical call against a policy (exit 1 if blocked)")
    s.add_argument("policy")
    s.add_argument("--tool", required=True)
    s.add_argument("--agent", default="agent")
    s.add_argument("--trust", type=float, default=None)
    s.add_argument("--args", help="JSON object of tool arguments")
    s.add_argument("--evidence", help="JSON object of evidence")
    s.add_argument("--result", help="JSON result to post-evaluate as well")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser(
        "proxy",
        help="run an MCP stdio proxy enforcing the policy: typed-rails proxy --policy p.yaml -- <server cmd>",
    )
    s.add_argument("--policy", required=True)
    s.add_argument("--evidence", help="evidence store file (JSONL, append-only)")
    s.add_argument("--agent", default="mcp-client", help="agent name to attribute the calls to")
    s.add_argument("--static-evidence", help="JSON object merged into the evidence of every call")
    s.add_argument("--hmac-key-env", help="environment variable holding the HMAC key used to sign evidence")
    s.add_argument(
        "--no-hide", action="store_true", help="do not remove statically denied tools from tools/list"
    )
    s.add_argument("command", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    s.set_defaults(func=cmd_proxy)

    s = sub.add_parser("evidence", help="inspect an evidence store")
    s.add_argument("file")
    s.add_argument("--hmac-key-env")
    es = s.add_subparsers(dest="evidence_command", required=True)
    v = es.add_parser("verify", help="verify the hash chain (and signatures)")
    v.set_defaults(func=cmd_evidence)
    sh = es.add_parser("show", help="print records")
    sh.add_argument("--last", type=int, default=0)
    sh.add_argument("--json", action="store_true")
    sh.set_defaults(func=cmd_evidence)
    ex = es.add_parser("export", help="re-export the store")
    ex.add_argument("out")
    ex.set_defaults(func=cmd_evidence)

    s = sub.add_parser("metrics", help="governance metrics from an evidence store")
    s.add_argument("file")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_metrics)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except PolicyCompileError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    except (OSError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
