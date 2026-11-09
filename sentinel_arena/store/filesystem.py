"""Filesystem store - JSON files under ``$ARENA_DATA_DIR/store``.

The zero-dependency default. Same contract as :class:`SqlStore`; the two are
tested against the same suite. Writes are atomic (temp file + replace) and
guarded by a process lock, so concurrent engagement threads don't corrupt a file.
Heavy per-engagement artifacts are not duplicated here - only the index record.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .base import DEFAULT_TENANT, Store, now_iso


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-._" else "_" for c in name)[:200]


class FilesystemStore(Store):
    def __init__(self, data_dir: str | Path) -> None:
        self.root = Path(data_dir) / "store"
        for sub in ("tenants", "targets", "campaigns", "engagements"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    # --- io helpers -----------------------------------------------------
    def _write(self, path: Path, data: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    def _read(self, path: Path) -> dict | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _read_all(self, sub: str) -> list[dict]:
        out = []
        for p in (self.root / sub).glob("*.json"):
            d = self._read(p)
            if d is not None:
                out.append(d)
        return out

    # --- tenants --------------------------------------------------------
    def ensure_tenant(self, tenant_id: str, name: str | None = None) -> dict:
        with self._lock:
            path = self.root / "tenants" / f"{_safe(tenant_id)}.json"
            existing = self._read(path)
            if existing:
                return existing
            rec = {"id": tenant_id, "name": name or tenant_id, "created_at": now_iso()}
            self._write(path, rec)
            return rec

    def get_tenant(self, tenant_id: str) -> dict | None:
        return self._read(self.root / "tenants" / f"{_safe(tenant_id)}.json")

    def list_tenants(self) -> list[dict]:
        return self._read_all("tenants")

    # --- targets --------------------------------------------------------
    def _target_path(self, tenant_id: str, host: str) -> Path:
        return self.root / "targets" / f"{_safe(tenant_id)}__{_safe(host)}.json"

    def upsert_target(self, tenant_id: str, host: str, *, ownership_proven: bool,
                      proof_method: str | None = None,
                      proof_expires_at: str | None = None) -> dict:
        self.ensure_tenant(tenant_id)
        with self._lock:
            path = self._target_path(tenant_id, host)
            rec = self._read(path) or {"tenant_id": tenant_id, "host": host,
                                       "created_at": now_iso()}
            rec.update({"ownership_proven": ownership_proven,
                        "proof_method": proof_method,
                        "proof_expires_at": proof_expires_at,
                        "updated_at": now_iso()})
            self._write(path, rec)
            return rec

    def get_target(self, tenant_id: str, host: str) -> dict | None:
        return self._read(self._target_path(tenant_id, host))

    def list_targets(self, tenant_id: str) -> list[dict]:
        return [t for t in self._read_all("targets")
                if t.get("tenant_id") == tenant_id]

    # --- campaigns ------------------------------------------------------
    def save_campaign(self, record: dict) -> dict:
        self.ensure_tenant(record.get("tenant_id", DEFAULT_TENANT))
        with self._lock:
            record.setdefault("tenant_id", DEFAULT_TENANT)
            self._write(self.root / "campaigns" / f"{_safe(record['id'])}.json", record)
            return record

    def get_campaign(self, campaign_id: str) -> dict | None:
        return self._read(self.root / "campaigns" / f"{_safe(campaign_id)}.json")

    def list_campaigns(self, tenant_id: str | None = None,
                       limit: int = 100) -> list[dict]:
        rows = self._read_all("campaigns")
        if tenant_id is not None:
            rows = [r for r in rows if r.get("tenant_id") == tenant_id]
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]

    # --- engagements ----------------------------------------------------
    def save_engagement(self, record: dict) -> dict:
        self.ensure_tenant(record.get("tenant_id", DEFAULT_TENANT))
        with self._lock:
            record.setdefault("tenant_id", DEFAULT_TENANT)
            self._write(self.root / "engagements" / f"{_safe(record['id'])}.json", record)
            return record

    def get_engagement(self, engagement_id: str) -> dict | None:
        return self._read(self.root / "engagements" / f"{_safe(engagement_id)}.json")

    def list_engagements(self, tenant_id: str | None = None,
                         limit: int = 200) -> list[dict]:
        rows = self._read_all("engagements")
        if tenant_id is not None:
            rows = [r for r in rows if r.get("tenant_id") == tenant_id]
        rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
        return rows[:limit]
