"""The engagement event store — append-only source of truth for replay.

Two kinds of events flow through here:

* **Range traffic** — every HTTP request the bundled app serves (actor, path,
  status, markers). This is the "log store" the blue team queries to separate
  attack from benign traffic.
* **Engagement events** — referee-level facts: actions taken, findings,
  detections, scoring, tick boundaries.

Stored as JSONL (one object per line) so a run can be replayed offline. The
tamper-evident authorization audit trail is separate (``authz.AuditLog``); this
store is the richer, analytics-friendly record.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from pydantic import BaseModel, Field


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Event(BaseModel):
    ts: str = Field(default_factory=_now)
    tick: int = -1
    kind: str  # e.g. "request", "action", "finding", "detection", "score", "tick"
    team: str = ""  # "red" | "blue" | "range" | "system"
    actor: str = ""
    summary: str = ""
    data: dict = Field(default_factory=dict)


class EventStore:
    """Append-only JSONL event store. Thread-safe appends within a process."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._subscribers: list = []

    def subscribe(self, callback) -> None:
        """Register a callback(Event) invoked on every append (for live streams)."""
        self._subscribers.append(callback)

    def append(self, event: Event) -> Event:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(event.model_dump_json() + "\n")
                fh.flush()
        for cb in list(self._subscribers):
            try:
                cb(event)
            except Exception:
                pass  # a bad subscriber must never break the engagement
        return event

    def emit(self, **kwargs) -> Event:
        return self.append(Event(**kwargs))

    def __iter__(self) -> Iterator[Event]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield Event.model_validate_json(line)

    def query(
        self,
        *,
        kind: str | None = None,
        team: str | None = None,
        actor: str | None = None,
        since_tick: int | None = None,
    ) -> list[Event]:
        """Simple structured query over the log — the blue team's lens on events."""
        out = []
        for e in self:
            if kind is not None and e.kind != kind:
                continue
            if team is not None and e.team != team:
                continue
            if actor is not None and e.actor != actor:
                continue
            if since_tick is not None and e.tick < since_tick:
                continue
            out.append(e)
        return out


class InMemoryEventSink:
    """Lightweight sink the range app writes request records into, mirrored to
    an :class:`EventStore`. Kept separate so the app does not depend on file I/O.
    """

    def __init__(self, store: EventStore) -> None:
        self.store = store
        self.requests: list[dict] = []
        self._lock = threading.Lock()

    def record_request(self, *, actor: str, method: str, path: str, status: int,
                       marker: str = "", tick: int = -1) -> None:
        rec = {"actor": actor, "method": method, "path": path, "status": status,
               "marker": marker}
        with self._lock:
            self.requests.append(rec)
        self.store.emit(
            kind="request", team="range", actor=actor, tick=tick,
            summary=f"{method} {path} -> {status}", data=rec,
        )
