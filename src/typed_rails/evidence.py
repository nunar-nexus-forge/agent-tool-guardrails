# SPDX-License-Identifier: Apache-2.0
"""The Evidence Store: an append-only, hash-chained (optionally HMAC-signed) audit log.

Every record includes the hash of the previous record, so removing, reordering or editing
any record breaks the chain and is detected by :meth:`EvidenceStore.verify`. With an HMAC
key, records are also signed so that a party without the key cannot re-write the chain.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def digest(obj: Any) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


@dataclass
class EvidenceRecord:
    index: int
    t: float
    kind: str  # decision | approval | note | result
    call_id: str | None = None
    agent: str | None = None
    tool: str | None = None
    phase: str | None = None
    action: str | None = None
    allowed: bool | None = None
    rails: list[dict[str, Any]] = field(default_factory=list)
    args_digest: str | None = None
    result_digest: str | None = None
    redactions: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    policy_hash: str | None = None
    prev_hash: str = GENESIS
    hash: str = ""
    signature: str | None = None

    def body(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("hash", None)
        d.pop("signature", None)
        return d

    def compute_hash(self) -> str:
        return digest(self.body())

    def compute_signature(self, key: bytes) -> str:
        return hmac.new(key, self.hash.encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EvidenceRecord:
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class VerificationResult:
    ok: bool
    records: int
    first_invalid: int | None = None
    reason: str | None = None

    def __str__(self) -> str:
        if self.ok:
            return f"OK: {self.records} record(s), chain intact"
        return f"TAMPERED at record {self.first_invalid}: {self.reason} ({self.records} record(s))"


def _key_bytes(key: bytes | str | None) -> bytes | None:
    if key is None:
        return None
    return key.encode("utf-8") if isinstance(key, str) else key


class EvidenceStore:
    """Append-only evidence log, in memory and optionally mirrored to a JSONL file."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        hmac_key: bytes | str | None = None,
        autoload: bool = True,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self._key = _key_bytes(hmac_key)
        self._records: list[EvidenceRecord] = []
        if self.path is not None and autoload and self.path.exists():
            self._records = self._read(self.path)

    # -- reading ----------------------------------------------------------------

    @staticmethod
    def _read(path: Path) -> list[EvidenceRecord]:
        out: list[EvidenceRecord] = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(EvidenceRecord.from_dict(json.loads(line)))
        return out

    @classmethod
    def load(cls, path: str | os.PathLike[str], *, hmac_key: bytes | str | None = None) -> EvidenceStore:
        return cls(path, hmac_key=hmac_key, autoload=True)

    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterable[EvidenceRecord]:  # type: ignore[override]
        return iter(self._records)

    @property
    def last_hash(self) -> str:
        return self._records[-1].hash if self._records else GENESIS

    def query(
        self,
        *,
        agent: str | None = None,
        tool: str | None = None,
        action: str | None = None,
        kind: str | None = None,
        call_id: str | None = None,
    ) -> list[EvidenceRecord]:
        out = []
        for r in self._records:
            if agent is not None and r.agent != agent:
                continue
            if tool is not None and r.tool != tool:
                continue
            if action is not None and r.action != action:
                continue
            if kind is not None and r.kind != kind:
                continue
            if call_id is not None and r.call_id != call_id:
                continue
            out.append(r)
        return out

    # -- writing ----------------------------------------------------------------

    def append(self, kind: str, *, t: float | None = None, **fields: Any) -> EvidenceRecord:
        """Append a record. Field values are deep-copied first: a record is hashed when it is
        written, so the caller must not be able to alter it afterwards through a shared list or dict."""
        import time as _time

        fields = copy.deepcopy(fields)
        record = EvidenceRecord(
            index=len(self._records),
            t=t if t is not None else _time.time(),
            kind=kind,
            prev_hash=self.last_hash,
            **fields,
        )
        record.hash = record.compute_hash()
        if self._key is not None:
            record.signature = record.compute_signature(self._key)
        self._records.append(record)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record.to_dict(), default=str, ensure_ascii=False) + "\n")
        return record

    def export(self, path: str | os.PathLike[str]) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8") as fh:
            for r in self._records:
                fh.write(json.dumps(r.to_dict(), default=str, ensure_ascii=False) + "\n")
        return target

    # -- integrity ----------------------------------------------------------------

    def verify(self, *, hmac_key: bytes | str | None = None) -> VerificationResult:
        key = _key_bytes(hmac_key) if hmac_key is not None else self._key
        prev = GENESIS
        for i, r in enumerate(self._records):
            if r.index != i:
                return VerificationResult(False, len(self._records), i, f"index {r.index} != position {i}")
            if r.prev_hash != prev:
                return VerificationResult(False, len(self._records), i, "previous-hash link broken")
            if r.compute_hash() != r.hash:
                return VerificationResult(
                    False, len(self._records), i, "record content does not match its hash"
                )
            if key is not None and (
                not r.signature or not hmac.compare_digest(r.signature, r.compute_signature(key))
            ):
                return VerificationResult(False, len(self._records), i, "signature invalid or missing")
            prev = r.hash
        return VerificationResult(True, len(self._records))

    def merkle_root(self) -> str:
        """Merkle root over record hashes (a compact commitment you can publish or timestamp)."""
        level = [r.hash for r in self._records]
        if not level:
            return GENESIS
        while len(level) > 1:
            if len(level) % 2 == 1:
                level.append(level[-1])
            level = [
                hashlib.sha256((a + b).encode("utf-8")).hexdigest() for a, b in zip(level[0::2], level[1::2])
            ]
        return level[0]
