"""The Store interface + the record shapes it moves.

Records are plain JSON-serializable dicts so the API layer is storage-agnostic:
a campaign dict is exactly ``CampaignResult.model_dump()`` plus ``tenant_id`` and
``status``. Both the filesystem and SQL implementations honor this contract, and
``tests/test_store.py`` runs the same suite against both to prove parity.
"""

from __future__ import annotations

import abc
from datetime import datetime, timezone
from typing import Any

DEFAULT_TENANT = "default"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def campaign_to_record(result: Any, *, tenant_id: str, status: str = "done") -> dict:
    """CampaignResult (or a dict) -> the stored campaign record."""
    data = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    data["tenant_id"] = tenant_id
    data["status"] = status
    return data


class Store(abc.ABC):
    """Durable, multi-tenant persistence. Implementations must be safe to call
    from multiple threads (the API runs engagements on background threads)."""

    # --- tenants --------------------------------------------------------
    @abc.abstractmethod
    def ensure_tenant(self, tenant_id: str, name: str | None = None) -> dict:
        """Create the tenant if absent; return it. Idempotent."""

    @abc.abstractmethod
    def get_tenant(self, tenant_id: str) -> dict | None: ...

    @abc.abstractmethod
    def list_tenants(self) -> list[dict]: ...

    # --- targets (ownership state for a host) ---------------------------
    @abc.abstractmethod
    def upsert_target(self, tenant_id: str, host: str, *, ownership_proven: bool,
                      proof_method: str | None = None,
                      proof_expires_at: str | None = None) -> dict: ...

    @abc.abstractmethod
    def get_target(self, tenant_id: str, host: str) -> dict | None: ...

    @abc.abstractmethod
    def list_targets(self, tenant_id: str) -> list[dict]: ...

    # --- campaigns ------------------------------------------------------
    @abc.abstractmethod
    def save_campaign(self, record: dict) -> dict:
        """Insert or replace a campaign (and its vulnerabilities). Returns it."""

    @abc.abstractmethod
    def get_campaign(self, campaign_id: str) -> dict | None: ...

    @abc.abstractmethod
    def list_campaigns(self, tenant_id: str | None = None,
                       limit: int = 100) -> list[dict]:
        """Most recent first. ``tenant_id=None`` lists across all tenants."""

    # --- engagement index (metadata; artifacts live on disk) ------------
    @abc.abstractmethod
    def save_engagement(self, record: dict) -> dict: ...

    @abc.abstractmethod
    def get_engagement(self, engagement_id: str) -> dict | None: ...

    @abc.abstractmethod
    def list_engagements(self, tenant_id: str | None = None,
                         limit: int = 200) -> list[dict]: ...

    # --- lifecycle ------------------------------------------------------
    def close(self) -> None:  # optional for implementations that hold handles
        pass
