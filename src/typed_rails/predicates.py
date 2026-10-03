# SPDX-License-Identifier: Apache-2.0
"""A small, safe expression language for rail predicates.

Predicates are strings such as::

    tool == "transfer_funds" and args.amount > 1000
    evidence.anonymised == true
    agent.trust >= 0.7 and not matches(args.query, "(?i)drop\\s+table")
    count_pii(result) == 0

They are parsed once into an AST and evaluated against a plain dictionary namespace
(``tool``, ``args``, ``agent``, ``evidence``, ``session``, ``env``, ``time``, ``result``,
``phase``). Nothing is ``eval``'d, there is no attribute access on Python objects, and a
missing path evaluates to ``null`` instead of raising, so ``evidence.flag == true`` is simply
false when the evidence is absent.

Grammar (lowest to highest precedence)::

    or_expr    := and_expr ("or" and_expr)*
    and_expr   := not_expr ("and" not_expr)*
    not_expr   := "not" not_expr | comparison
    comparison := arith (COMP arith)?
                  COMP: == != < <= > >= in "not in" matches contains startswith endswith
    arith      := term (("+" | "-") term)*
    term       := factor (("*" | "/" | "%") factor)*
    factor     := ("-" | "+") factor | primary
    primary    := NUMBER | STRING | true | false | null | "[" list "]" | "(" expr ")"
                  | NAME "(" args ")" | path
    path       := NAME ("." NAME | "[" (STRING | NUMBER) "]")*
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .redaction import count_pii, find_pii

# --- errors ---------------------------------------------------------------------


class PredicateError(ValueError):
    pass


class PredicateSyntaxError(PredicateError):
    def __init__(self, message: str, position: int, source: str) -> None:
        super().__init__(f"{message} at position {position} in {source!r}")
        self.position = position
        self.source = source


# --- tokenizer ------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<number>\d+(?:\.\d+)?(?:[eE][-+]?\d+)?)
  | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<op>==|!=|<=|>=|<|>|\+|-|\*|/|%|\(|\)|\[|\]|,|\.)
    """,
    re.VERBOSE,
)

KEYWORDS = {
    "and",
    "or",
    "not",
    "in",
    "matches",
    "contains",
    "startswith",
    "endswith",
    "true",
    "false",
    "null",
}


@dataclass(frozen=True)
class Token:
    kind: str  # number | string | name | op | keyword | end
    value: str
    pos: int


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(source):
        m = _TOKEN_RE.match(source, pos)
        if m is None:
            raise PredicateSyntaxError(f"unexpected character {source[pos]!r}", pos, source)
        kind = m.lastgroup or "ws"
        text = m.group(kind)
        if kind != "ws":
            if kind == "name" and text in KEYWORDS:
                kind = "keyword"
            tokens.append(Token(kind, text, pos))
        pos = m.end()
    tokens.append(Token("end", "", len(source)))
    return tokens


# --- AST -------------------------------------------------------------------------


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Path:
    parts: tuple[str, ...]

    @property
    def dotted(self) -> str:
        return ".".join(self.parts)


@dataclass(frozen=True)
class ListExpr:
    items: tuple[Any, ...]


@dataclass(frozen=True)
class Unary:
    op: str
    operand: Any


@dataclass(frozen=True)
class Binary:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple[Any, ...]


Node = Literal | Path | ListExpr | Unary | Binary | Call

_COMPARISONS = {
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "in",
    "not in",
    "matches",
    "contains",
    "startswith",
    "endswith",
}


class Parser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.tokens = tokenize(source)
        self.i = 0

    def peek(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def expect(self, kind: str, value: str | None = None) -> Token:
        tok = self.peek()
        if tok.kind != kind or (value is not None and tok.value != value):
            want = value or kind
            raise PredicateSyntaxError(
                f"expected {want!r} but found {tok.value or 'end of input'!r}", tok.pos, self.source
            )
        return self.advance()

    def parse(self) -> Node:
        node = self.parse_or()
        tok = self.peek()
        if tok.kind != "end":
            raise PredicateSyntaxError(f"unexpected token {tok.value!r}", tok.pos, self.source)
        return node

    def parse_or(self) -> Node:
        node = self.parse_and()
        while self.peek().kind == "keyword" and self.peek().value == "or":
            self.advance()
            node = Binary("or", node, self.parse_and())
        return node

    def parse_and(self) -> Node:
        node = self.parse_not()
        while self.peek().kind == "keyword" and self.peek().value == "and":
            self.advance()
            node = Binary("and", node, self.parse_not())
        return node

    def parse_not(self) -> Node:
        if self.peek().kind == "keyword" and self.peek().value == "not":
            self.advance()
            return Unary("not", self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Node:
        left = self.parse_arith()
        tok = self.peek()
        op: str | None = None
        infix_keywords = ("in", "matches", "contains", "startswith", "endswith")
        if (tok.kind == "op" and tok.value in _COMPARISONS) or (
            tok.kind == "keyword" and tok.value in infix_keywords
        ):
            op = self.advance().value
        elif tok.kind == "keyword" and tok.value == "not":
            nxt = self.tokens[self.i + 1]
            if nxt.kind == "keyword" and nxt.value == "in":
                self.advance()
                self.advance()
                op = "not in"
        if op is None:
            return left
        right = self.parse_arith()
        return Binary(op, left, right)

    def parse_arith(self) -> Node:
        node = self.parse_term()
        while self.peek().kind == "op" and self.peek().value in ("+", "-"):
            op = self.advance().value
            node = Binary(op, node, self.parse_term())
        return node

    def parse_term(self) -> Node:
        node = self.parse_factor()
        while self.peek().kind == "op" and self.peek().value in ("*", "/", "%"):
            op = self.advance().value
            node = Binary(op, node, self.parse_factor())
        return node

    def parse_factor(self) -> Node:
        tok = self.peek()
        if tok.kind == "op" and tok.value in ("-", "+"):
            self.advance()
            return Unary(tok.value, self.parse_factor())
        return self.parse_primary()

    def parse_primary(self) -> Node:
        tok = self.advance()
        if tok.kind == "number":
            text = tok.value
            return Literal(float(text) if any(c in text for c in ".eE") else int(text))
        if tok.kind == "string":
            return Literal(_unquote(tok.value))
        if (
            tok.kind == "keyword"
            and tok.value in FUNCTIONS
            and self.peek().kind == "op"
            and self.peek().value == "("
        ):
            return self._parse_call(tok)
        if tok.kind == "keyword":
            if tok.value == "true":
                return Literal(True)
            if tok.value == "false":
                return Literal(False)
            if tok.value == "null":
                return Literal(None)
            raise PredicateSyntaxError(f"unexpected keyword {tok.value!r}", tok.pos, self.source)
        if tok.kind == "op" and tok.value == "(":
            node = self.parse_or()
            self.expect("op", ")")
            return node
        if tok.kind == "op" and tok.value == "[":
            items: list[Node] = []
            if not (self.peek().kind == "op" and self.peek().value == "]"):
                items.append(self.parse_or())
                while self.peek().kind == "op" and self.peek().value == ",":
                    self.advance()
                    items.append(self.parse_or())
            self.expect("op", "]")
            return ListExpr(tuple(items))
        if tok.kind == "name":
            if self.peek().kind == "op" and self.peek().value == "(":
                return self._parse_call(tok)
            parts = [tok.value]
            while True:
                nxt = self.peek()
                if nxt.kind == "op" and nxt.value == ".":
                    self.advance()
                    parts.append(self.expect("name").value)
                elif nxt.kind == "op" and nxt.value == "[":
                    self.advance()
                    key = self.advance()
                    negative = False
                    if key.kind == "op" and key.value == "-":
                        negative = True
                        key = self.advance()
                    if key.kind == "string" and not negative:
                        parts.append(_unquote(key.value))
                    elif key.kind == "number":
                        parts.append(("-" if negative else "") + key.value)
                    else:
                        raise PredicateSyntaxError("index must be a string or number", key.pos, self.source)
                    self.expect("op", "]")
                else:
                    break
            return Path(tuple(parts))
        raise PredicateSyntaxError(f"unexpected token {tok.value or 'end of input'!r}", tok.pos, self.source)

    def _parse_call(self, tok: Token) -> Node:
        self.expect("op", "(")
        args: list[Node] = []
        if not (self.peek().kind == "op" and self.peek().value == ")"):
            args.append(self.parse_or())
            while self.peek().kind == "op" and self.peek().value == ",":
                self.advance()
                args.append(self.parse_or())
        self.expect("op", ")")
        if tok.value not in FUNCTIONS and tok.value not in _RUNTIME_FUNCTION_NAMES:
            raise PredicateSyntaxError(f"unknown function {tok.value!r}", tok.pos, self.source)
        return Call(tok.value, tuple(args))


def _unquote(text: str) -> str:
    body = text[1:-1]
    return body.encode("utf-8").decode("unicode_escape") if "\\" in body else body


# --- functions -------------------------------------------------------------------


def _as_text(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    try:
        import json

        return json.dumps(x, sort_keys=True, default=str)
    except Exception:  # pragma: no cover
        return str(x)


def _f_len(x: Any) -> int:
    if x is None:
        return 0
    try:
        return len(x)
    except TypeError:
        return len(str(x))


def _f_keys(x: Any) -> list[Any]:
    return list(x.keys()) if isinstance(x, Mapping) else []


def _f_values(x: Any) -> list[Any]:
    return list(x.values()) if isinstance(x, Mapping) else []


def _f_matches(text: Any, pattern: Any) -> bool:
    if text is None or pattern is None:
        return False
    return _regex(str(pattern)).search(_as_text(text)) is not None


def _f_number(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


FUNCTIONS: dict[str, Callable[..., Any]] = {
    "len": _f_len,
    "lower": lambda s: _as_text(s).lower(),
    "upper": lambda s: _as_text(s).upper(),
    "str": _as_text,
    "int": lambda x: int(float(x)) if x is not None else None,
    "float": _f_number,
    "abs": lambda x: abs(x) if isinstance(x, (int, float)) else None,
    "min": lambda *xs: min(x for x in xs if x is not None) if any(x is not None for x in xs) else None,
    "max": lambda *xs: max(x for x in xs if x is not None) if any(x is not None for x in xs) else None,
    "sum": lambda xs: sum(x for x in (xs or []) if isinstance(x, (int, float))),
    "any": lambda xs: any(bool(x) for x in (xs or [])),
    "all": lambda xs: all(bool(x) for x in (xs or [])),
    "exists": lambda x: x is not None,
    "keys": _f_keys,
    "values": _f_values,
    "matches": _f_matches,
    "contains": lambda a, b: (
        (b in a) if isinstance(a, (str, list, tuple, Mapping)) and b is not None else False
    ),
    "startswith": lambda a, b: (
        _as_text(a).startswith(_as_text(b)) if a is not None and b is not None else False
    ),
    "endswith": lambda a, b: _as_text(a).endswith(_as_text(b)) if a is not None and b is not None else False,
    "now": lambda: time.time(),
    "age": lambda ts: (time.time() - float(ts)) if ts is not None else None,
    "count_pii": lambda x: count_pii(x),
    "has_pii": lambda x: count_pii(x) > 0,
    "pii_kinds": lambda x: sorted({m.kind for m in find_pii(_as_text(x))}),
    "round": lambda x, n=0: round(x, int(n)) if isinstance(x, (int, float)) else None,
}

# Names that an engine may provide at evaluation time (rate limits, custom hooks).
_RUNTIME_FUNCTION_NAMES = {"rate", "custom"}

_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def _regex(pattern: str) -> re.Pattern[str]:
    compiled = _REGEX_CACHE.get(pattern)
    if compiled is None:
        if len(pattern) > 500:
            raise PredicateError("regular expression too long")
        compiled = re.compile(pattern)
        _REGEX_CACHE[pattern] = compiled
    return compiled


# --- evaluation ------------------------------------------------------------------


def resolve_path(namespace: Mapping[str, Any], parts: Sequence[str]) -> Any:
    current: Any = namespace
    for part in parts:
        if isinstance(current, Mapping):
            if part in current:
                current = current[part]
            elif part.isdigit() and int(part) in current:
                current = current[int(part)]
            else:
                return None
        elif isinstance(current, (list, tuple)):
            if part.lstrip("-").isdigit():
                idx = int(part)
                current = current[idx] if -len(current) <= idx < len(current) else None
            else:
                return None
        else:
            return None
    return current


def _compare(op: str, a: Any, b: Any) -> bool:
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    if op in ("<", "<=", ">", ">="):
        if a is None or b is None:
            return False
        try:
            if op == "<":
                return bool(a < b)
            if op == "<=":
                return bool(a <= b)
            if op == ">":
                return bool(a > b)
            return bool(a >= b)
        except TypeError:
            return False
    if op == "in":
        return _contains(b, a)
    if op == "not in":
        return not _contains(b, a)
    if op == "matches":
        return _f_matches(a, b)
    if op == "contains":
        return _contains(a, b)
    if op == "startswith":
        return bool(FUNCTIONS["startswith"](a, b))
    if op == "endswith":
        return bool(FUNCTIONS["endswith"](a, b))
    raise PredicateError(f"unknown comparison {op!r}")


def _contains(container: Any, item: Any) -> bool:
    if container is None or item is None:
        return False
    if isinstance(container, (str, list, tuple, Mapping)):
        try:
            return item in container
        except TypeError:
            return False
    return False


def _arith(op: str, a: Any, b: Any) -> Any:
    if op == "+" and isinstance(a, str) and isinstance(b, str):
        return a + b
    if (
        not isinstance(a, (int, float))
        or not isinstance(b, (int, float))
        or isinstance(a, bool)
        or isinstance(b, bool)
    ):
        return None
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "/":
        return a / b if b != 0 else None
    if op == "%":
        return a % b if b != 0 else None
    raise PredicateError(f"unknown operator {op!r}")


def evaluate_node(
    node: Node, namespace: Mapping[str, Any], functions: Mapping[str, Callable[..., Any]] | None = None
) -> Any:
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Path):
        return resolve_path(namespace, node.parts)
    if isinstance(node, ListExpr):
        return [evaluate_node(item, namespace, functions) for item in node.items]
    if isinstance(node, Unary):
        value = evaluate_node(node.operand, namespace, functions)
        if node.op == "not":
            return not bool(value)
        if node.op == "-":
            return -value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        return value
    if isinstance(node, Binary):
        if node.op == "and":
            return bool(evaluate_node(node.left, namespace, functions)) and bool(
                evaluate_node(node.right, namespace, functions)
            )
        if node.op == "or":
            return bool(evaluate_node(node.left, namespace, functions)) or bool(
                evaluate_node(node.right, namespace, functions)
            )
        left = evaluate_node(node.left, namespace, functions)
        right = evaluate_node(node.right, namespace, functions)
        if node.op in _COMPARISONS:
            return _compare(node.op, left, right)
        return _arith(node.op, left, right)
    if isinstance(node, Call):
        fn = (functions or {}).get(node.name) or FUNCTIONS.get(node.name)
        if fn is None:
            raise PredicateError(f"function {node.name!r} is not available in this context")
        args = [evaluate_node(a, namespace, functions) for a in node.args]
        try:
            return fn(*args)
        except PredicateError:
            raise
        except Exception as exc:
            raise PredicateError(f"error in {node.name}(): {exc}") from exc
    raise PredicateError(f"cannot evaluate {node!r}")  # pragma: no cover


def collect_paths(node: Node) -> list[str]:
    out: list[str] = []

    def walk(n: Any) -> None:
        if isinstance(n, Path):
            out.append(n.dotted)
        elif isinstance(n, ListExpr):
            for item in n.items:
                walk(item)
        elif isinstance(n, Unary):
            walk(n.operand)
        elif isinstance(n, Binary):
            walk(n.left)
            walk(n.right)
        elif isinstance(n, Call):
            for a in n.args:
                walk(a)

    walk(node)
    return list(dict.fromkeys(out))


def collect_functions(node: Node) -> list[str]:
    out: list[str] = []

    def walk(n: Any) -> None:
        if isinstance(n, Call):
            out.append(n.name)
            for a in n.args:
                walk(a)
        elif isinstance(n, ListExpr):
            for item in n.items:
                walk(item)
        elif isinstance(n, Unary):
            walk(n.operand)
        elif isinstance(n, Binary):
            walk(n.left)
            walk(n.right)

    walk(node)
    return list(dict.fromkeys(out))


class Predicate:
    """A compiled predicate. Construction validates the syntax."""

    def __init__(self, source: str) -> None:
        if not isinstance(source, str) or not source.strip():
            raise PredicateSyntaxError("empty predicate", 0, str(source))
        self.source = source.strip()
        self.ast: Node = Parser(self.source).parse()
        self.paths: list[str] = collect_paths(self.ast)
        self.functions: list[str] = collect_functions(self.ast)

    def evaluate(
        self, namespace: Mapping[str, Any], functions: Mapping[str, Callable[..., Any]] | None = None
    ) -> bool:
        value = evaluate_node(self.ast, namespace, functions)
        if isinstance(value, float) and math.isnan(value):
            return False
        return bool(value)

    def explain(self, namespace: Mapping[str, Any]) -> dict[str, Any]:
        """The values of every path the predicate reads (what the evidence looked like)."""
        return {p: resolve_path(namespace, tuple(p.split("."))) for p in self.paths}

    @property
    def is_static(self) -> bool:
        """True when the predicate only depends on the tool name and the agent (no arguments,
        evidence or results), so it can be evaluated before a call - used to hide tools."""
        allowed = ("tool", "agent", "phase")
        return all(p == "tool" or p.split(".")[0] in allowed for p in self.paths) and not self.functions

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Predicate) and other.source == self.source

    def __hash__(self) -> int:
        return hash(self.source)

    def __repr__(self) -> str:
        return f"Predicate({self.source!r})"
