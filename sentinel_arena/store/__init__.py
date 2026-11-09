"""Durable, multi-tenant persistence - the single seam the rest of the platform
reads and writes state through.

Two interchangeable implementations behind one :class:`Store` interface:

* :class:`FilesystemStore` - JSON on disk under ``$ARENA_DATA_DIR`` (the default;
  no extra dependency; preserves the pre-existing on-disk layout so nothing is
  lost on upgrade).
* :class:`SqlStore` - SQLAlchemy models that run unchanged on **SQLite**
  (dev/tests) and **Postgres** (production: set ``ARENA_DB_URL`` and install a
  psycopg driver). This is the path that scales to many app replicas.

Selection (``get_store``):

* ``ARENA_DB_URL`` set            -> SqlStore(that url)
* ``ARENA_STORE=sql`` (no url)    -> SqlStore(sqlite file under the data dir)
* otherwise                        -> FilesystemStore(data dir)

Every record is scoped by ``tenant_id`` (default ``"default"``) so multi-tenancy
is built in from the foundation, not retrofitted. Heavy per-engagement artifacts
(events/audit JSONL, reports) stay as files; the store holds the metadata and a
pointer to them - the standard blob pattern.
"""

from __future__ import annotations

import os
from pathlib import Path

from .base import DEFAULT_TENANT, Store

__all__ = ["Store", "DEFAULT_TENANT", "get_store", "reset_store"]

_STORE: Store | None = None


def _build_store() -> Store:
    data_dir = Path(os.environ.get("ARENA_DATA_DIR", "var"))
    url = os.environ.get("ARENA_DB_URL")
    want_sql = bool(url) or os.environ.get("ARENA_STORE", "").lower() == "sql"
    if want_sql:
        from .sql import SqlStore
        if not url:
            data_dir.mkdir(parents=True, exist_ok=True)
            url = f"sqlite:///{(data_dir / 'sentinel.db').as_posix()}"
        return SqlStore(url)
    from .filesystem import FilesystemStore
    return FilesystemStore(data_dir)


def get_store() -> Store:
    """Return the process-wide store, building it on first use."""
    global _STORE
    if _STORE is None:
        _STORE = _build_store()
    return _STORE


def reset_store() -> None:
    """Drop the cached store (tests, or after changing env)."""
    global _STORE
    _STORE = None
