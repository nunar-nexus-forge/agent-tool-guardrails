# SPDX-License-Identifier: Apache-2.0
"""Policy-driven memory sharding.

Each agent's memory is split into a **policy** shard (rules, permissions, compliance
limits), a **context** shard (environmental state and inference results) and an
**analytics** shard (aggregates and metrics). A :class:`ShardPolicy` decides
``P(process, shard) -> allow | deny`` for every access; a violation is recorded, the access
is refused and a callback lets the caller penalise the offending process's trust.
"""

from __future__ import annotations

import enum
import fnmatch
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .predicates import Predicate


class Shard(str, enum.Enum):
    POLICY = "policy"
    CONTEXT = "context"
    ANALYTICS = "analytics"


class ShardAccessDenied(PermissionError):
    def __init__(self, access: ShardAccess) -> None:
        super().__init__(f"{access.process} may not {access.op} {access.shard} shard ({access.reason})")
        self.access = access


@dataclass
class ShardAccess:
    t: float
    process: str
    shard: str
    op: str
    key: str | None
    allowed: bool
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "t": self.t,
            "process": self.process,
            "shard": self.shard,
            "op": self.op,
            "key": self.key,
            "allowed": self.allowed,
            "reason": self.reason,
        }


class ShardPolicy:
    """Which processes may access which shard.

    ``rules`` maps a shard name to the process patterns allowed to read *and* write it
    (``write_rules`` narrows writes further). ``min_trust`` per shard gates by trust.
    An optional ``predicate`` over ``{process, shard, op, key, trust}`` adds arbitrary logic.
    """

    def __init__(
        self,
        rules: Mapping[str, Iterable[str]] | None = None,
        *,
        write_rules: Mapping[str, Iterable[str]] | None = None,
        min_trust: Mapping[str, float] | None = None,
        predicate: Predicate | str | None = None,
    ) -> None:
        default = {
            Shard.POLICY.value: ["governor", "policy-engine"],
            Shard.CONTEXT.value: ["*"],
            Shard.ANALYTICS.value: ["*"],
        }
        self.rules = {k: list(v) for k, v in (rules or default).items()}
        self.write_rules = {k: list(v) for k, v in (write_rules or {}).items()}
        self.min_trust = dict(min_trust or {})
        self.predicate = Predicate(predicate) if isinstance(predicate, str) else predicate

    def decide(
        self, process: str, shard: str, op: str, key: str | None = None, trust: float = 1.0
    ) -> tuple[bool, str]:
        allowed_patterns = self.rules.get(shard)
        if allowed_patterns is None or not any(fnmatch.fnmatchcase(process, p) for p in allowed_patterns):
            return False, f"process not allowed on {shard} shard"
        if (
            op in ("write", "delete")
            and shard in self.write_rules
            and not any(fnmatch.fnmatchcase(process, p) for p in self.write_rules[shard])
        ):
            return False, f"process may not {op} {shard} shard"
        threshold = self.min_trust.get(shard)
        if threshold is not None and trust < threshold:
            return False, f"trust {trust:.2f} below {threshold:.2f} for {shard} shard"
        if self.predicate is not None and not self.predicate.evaluate(
            {"process": process, "shard": shard, "op": op, "key": key, "trust": trust}
        ):
            return False, f"predicate {self.predicate.source!r} false"
        return True, "allowed"


class ShardedMemory:
    def __init__(
        self,
        agent: str,
        policy: ShardPolicy | None = None,
        *,
        trust_fn: Callable[[str], float] | None = None,
        on_violation: Callable[[ShardAccess], None] | None = None,
        beta: float = 0.7,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.agent = agent
        self.policy = policy or ShardPolicy()
        self.trust_fn = trust_fn
        self.on_violation = on_violation
        self.beta = beta
        self._clock = clock
        self.shards: dict[str, dict[str, Any]] = {s.value: {} for s in Shard}
        self.accesses: list[ShardAccess] = []

    # -- gate -------------------------------------------------------------------

    def _gate(self, process: str, shard: Shard | str, op: str, key: str | None) -> ShardAccess:
        shard_name = Shard(shard).value
        trust = self.trust_fn(process) if self.trust_fn is not None else 1.0
        allowed, reason = self.policy.decide(process, shard_name, op, key, trust)
        access = ShardAccess(self._clock(), process, shard_name, op, key, allowed, reason)
        self.accesses.append(access)
        if not allowed:
            if self.on_violation is not None:
                self.on_violation(access)
            raise ShardAccessDenied(access)
        return access

    # -- operations -----------------------------------------------------------------

    def read(self, process: str, shard: Shard | str, key: str, default: Any = None) -> Any:
        self._gate(process, shard, "read", key)
        return self.shards[Shard(shard).value].get(key, default)

    def write(self, process: str, shard: Shard | str, key: str, value: Any) -> None:
        self._gate(process, shard, "write", key)
        self.shards[Shard(shard).value][key] = value

    def delete(self, process: str, shard: Shard | str, key: str) -> None:
        self._gate(process, shard, "delete", key)
        self.shards[Shard(shard).value].pop(key, None)

    def update_context(
        self,
        process: str,
        key: str,
        observed: float | list[float] | tuple[float, ...],
        beta: float | None = None,
    ) -> Any:
        """Temporal integration ``X(t+Δt) = β·X(t) + (1 − β)·x_obs`` on the context shard."""
        b = self.beta if beta is None else beta
        self._gate(process, Shard.CONTEXT, "write", key)
        store = self.shards[Shard.CONTEXT.value]
        current = store.get(key)
        if current is None:
            store[key] = list(observed) if isinstance(observed, (list, tuple)) else observed
            return store[key]
        if isinstance(observed, (list, tuple)):
            cur = list(current) if isinstance(current, (list, tuple)) else [float(current)] * len(observed)
            store[key] = [b * c + (1 - b) * o for c, o in zip(cur, observed)]
        else:
            base = float(current[0]) if isinstance(current, (list, tuple)) else float(current)
            store[key] = b * base + (1 - b) * float(observed)
        return store[key]

    # -- reporting -------------------------------------------------------------------

    @property
    def violations(self) -> list[ShardAccess]:
        return [a for a in self.accesses if not a.allowed]

    def compliance(self) -> float:
        return (sum(1 for a in self.accesses if a.allowed) / len(self.accesses)) if self.accesses else 1.0

    def lineage(self, key: str | None = None) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self.accesses if key is None or a.key == key]
