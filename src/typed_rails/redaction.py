# SPDX-License-Identifier: Apache-2.0
"""PII detection and field masking used by redaction actions and the ``count_pii`` predicate function."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?![\w.])"),
    "ssn": re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
    "credit_card": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    "ipv4": re.compile(r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"),
    "api_key": re.compile(r"\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9_-]{16,}\b"),
}

CUSTOM_PATTERNS: dict[str, re.Pattern[str]] = {}


def register_pattern(kind: str, pattern: str) -> None:
    """Register an additional PII pattern (project-specific identifiers, employee ids, ...)."""
    CUSTOM_PATTERNS[kind] = re.compile(pattern)


@dataclass(frozen=True)
class PIIMatch:
    kind: str
    start: int
    end: int
    value: str


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_pii(text: str, kinds: Iterable[str] | None = None) -> list[PIIMatch]:
    if not isinstance(text, str) or not text:
        return []
    wanted = set(kinds) if kinds is not None else None
    matches: list[PIIMatch] = []
    for kind, pattern in {**_PATTERNS, **CUSTOM_PATTERNS}.items():
        if wanted is not None and kind not in wanted:
            continue
        for m in pattern.finditer(text):
            value = m.group(0)
            if kind == "credit_card":
                digits = re.sub(r"\D", "", value)
                if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                    continue
            if kind == "phone" and any(
                kind2 == "credit_card" and s <= m.start() < e
                for kind2, s, e in ((x.kind, x.start, x.end) for x in matches)
            ):
                continue
            matches.append(PIIMatch(kind, m.start(), m.end(), value))
    matches.sort(key=lambda x: (x.start, -x.end))
    # drop overlaps (keep the earliest/longest)
    out: list[PIIMatch] = []
    last_end = -1
    for pm in matches:
        if pm.start >= last_end:
            out.append(pm)
            last_end = pm.end
    return out


def redact_text(text: str, mask: str = "[REDACTED:{kind}]", kinds: Iterable[str] | None = None) -> str:
    matches = find_pii(text, kinds)
    if not matches:
        return text
    out = []
    pos = 0
    for m in matches:
        out.append(text[pos : m.start])
        out.append(mask.format(kind=m.kind))
        pos = m.end
    out.append(text[pos:])
    return "".join(out)


def count_pii(value: Any, kinds: Iterable[str] | None = None) -> int:
    """Number of PII matches in a string, or in all string leaves of a nested structure."""
    total = 0
    for leaf in _string_leaves(value):
        total += len(find_pii(leaf, kinds))
    return total


def _string_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _string_leaves(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _string_leaves(v)
    elif value is not None and not isinstance(value, (int, float, bool)):
        yield json.dumps(value, default=str)


def _path_matches(path: Sequence[str], pattern: str) -> bool:
    parts = pattern.split(".")
    if parts and parts[0] in ("args", "result"):
        parts = parts[1:]
    if not parts:
        return True
    if len(parts) > len(path) and "**" not in parts:
        return False
    i = 0
    for pat in parts:
        if pat == "**":
            return True
        if i >= len(path):
            return False
        if pat != "*" and pat != path[i]:
            return False
        i += 1
    return i == len(path) or parts[-1] == "*"


def redact_value(
    value: Any,
    fields: Sequence[str] | None = None,
    *,
    detect: bool = True,
    mask: str = "[REDACTED:{kind}]",
    field_mask: str = "[REDACTED]",
    kinds: Iterable[str] | None = None,
) -> tuple[Any, list[str]]:
    """Return ``(redacted_copy, redacted_paths)``.

    ``fields`` are dotted paths (``args.customer.email``, ``args.*``, ``**``) that are masked
    whole. When ``detect`` is true, every remaining string leaf is scanned for PII and the
    matches are masked in place.
    """
    redacted: list[str] = []
    patterns = list(fields or [])

    def walk(node: Any, path: tuple[str, ...]) -> Any:
        if any(_path_matches(path, p) for p in patterns) and path:
            redacted.append(".".join(path))
            return field_mask
        if isinstance(node, dict):
            return {k: walk(v, path + (str(k),)) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, path + (str(i),)) for i, v in enumerate(node)]
        if isinstance(node, tuple):
            return tuple(walk(v, path + (str(i),)) for i, v in enumerate(node))
        if isinstance(node, str) and detect:
            new = redact_text(node, mask, kinds)
            if new != node:
                redacted.append(".".join(path) or "$")
            return new
        return node

    return walk(copy.deepcopy(value), ()), redacted


Redactor = Callable[[Any, Sequence[str] | None], tuple[Any, list[str]]]
