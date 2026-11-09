"""Tamper-evident, append-only audit trail.

Every authorization-relevant event (challenge issued, authorized, denied,
revoked, and every per-request scope check) is written as one line of JSON to
an append-only log. Each entry carries the SHA-256 hash of the previous entry,
forming a chain: altering or deleting any past entry breaks every hash after
it, which :meth:`AuditLog.verify_chain` detects.

The store is a JSONL file (one JSON object per line). The brief later moves the
event store to Parquet for analytics; this hash-chained JSONL is the source of
truth for integrity and replay.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

GENESIS_HASH = "0" * 64


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON bytes for hashing (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: str  # ISO-8601 UTC
    actor: str  # user_id or "system"
    action: str
    host: str
    scope_fingerprint: str
    outcome: str  # "allow" | "deny" | "info"
    detail: dict
    prev_hash: str
    entry_hash: str = ""

    def _hashable(self) -> dict:
        d = asdict(self)
        d.pop("entry_hash", None)
        return d

    def compute_hash(self) -> str:
        return hashlib.sha256(_canonical(self._hashable())).hexdigest()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, line: str) -> "AuditEntry":
        return cls(**json.loads(line))


class ChainBroken(Exception):
    """Raised when the audit chain fails integrity verification."""


class AuditLog:
    """Append-only hash-chained log backed by a JSONL file.

    Thread-safe for appends within a process. Across processes, point each at
    its own file (the brief runs one arena per host).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq, self._tip = self._load_tip()

    def _load_tip(self) -> tuple[int, str]:
        if not self.path.exists():
            return -1, GENESIS_HASH
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return -1, GENESIS_HASH
        entry = AuditEntry.from_json(last)
        return entry.seq, entry.entry_hash

    def append(
        self,
        *,
        actor: str,
        action: str,
        host: str = "",
        scope_fingerprint: str = "",
        outcome: str = "info",
        detail: dict | None = None,
    ) -> AuditEntry:
        with self._lock:
            seq = self._seq + 1
            partial = AuditEntry(
                seq=seq,
                timestamp=datetime.now(timezone.utc).isoformat(),
                actor=actor,
                action=action,
                host=host,
                scope_fingerprint=scope_fingerprint,
                outcome=outcome,
                detail=detail or {},
                prev_hash=self._tip,
            )
            entry_hash = partial.compute_hash()
            entry = AuditEntry(**{**asdict(partial), "entry_hash": entry_hash})
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(entry.to_json() + "\n")
                fh.flush()
            self._seq = seq
            self._tip = entry_hash
            return entry

    def __iter__(self) -> Iterator[AuditEntry]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield AuditEntry.from_json(line)

    def verify_chain(self) -> bool:
        """Return True iff the on-disk chain is intact. Raise :class:`ChainBroken`
        with the offending sequence number otherwise."""
        prev = GENESIS_HASH
        expected_seq = 0
        for entry in self:
            if entry.seq != expected_seq:
                raise ChainBroken(f"seq gap at {entry.seq} (expected {expected_seq})")
            if entry.prev_hash != prev:
                raise ChainBroken(f"prev_hash mismatch at seq {entry.seq}")
            if entry.compute_hash() != entry.entry_hash:
                raise ChainBroken(f"entry_hash mismatch at seq {entry.seq}")
            prev = entry.entry_hash
            expected_seq += 1
        return True
