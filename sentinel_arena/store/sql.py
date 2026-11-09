"""SQLAlchemy-backed store. Same models on SQLite (dev/tests) and Postgres (prod).

Production: ``ARENA_DB_URL=postgresql+psycopg://user:pw@host/db`` (install the
``psycopg`` driver). The audit *chain* that the gate writes stays file-based and
tamper-evident per engagement; this store holds assessment state (tenants,
targets, campaigns, findings, engagement index) that many app replicas share.

Postgres hardening (row-level security per ``tenant_id``, an append-only grant on
the findings/campaign tables, TLS) is described in ``docs/DEPLOYMENT.md`` and is a
database-config concern, not application code.
"""

from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, create_engine, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)
from sqlalchemy.pool import StaticPool

from .base import DEFAULT_TENANT, Store, now_iso


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[str] = mapped_column(String(64), default=now_iso)

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "created_at": self.created_at}


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    host: Mapped[str] = mapped_column(String(256), index=True)
    ownership_proven: Mapped[bool] = mapped_column(default=False)
    proof_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    proof_expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=now_iso)
    updated_at: Mapped[str] = mapped_column(String(64), default=now_iso)

    def to_dict(self) -> dict:
        return {"tenant_id": self.tenant_id, "host": self.host,
                "ownership_proven": self.ownership_proven,
                "proof_method": self.proof_method,
                "proof_expires_at": self.proof_expires_at,
                "created_at": self.created_at, "updated_at": self.updated_at}


class Campaign(Base):
    __tablename__ = "campaigns"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    target: Mapped[str] = mapped_column(String(256), default="")
    label: Mapped[str] = mapped_column(String(256), default="")
    depth: Mapped[str] = mapped_column(String(32), default="standard")
    status: Mapped[str] = mapped_column(String(32), default="done")
    created_at: Mapped[str] = mapped_column(String(64), default=now_iso)
    runs: Mapped[int] = mapped_column(default=0)
    posture_grade: Mapped[str] = mapped_column(String(2), default="F")
    mean_resilience: Mapped[float] = mapped_column(default=0.0)
    worst_resilience: Mapped[int] = mapped_column(default=0)
    best_resilience: Mapped[int] = mapped_column(default=0)
    attacker_win_rate: Mapped[float] = mapped_column(default=0.0)
    scenarios: Mapped[Any] = mapped_column(JSON, default=list)
    reds: Mapped[Any] = mapped_column(JSON, default=list)
    blues: Mapped[Any] = mapped_column(JSON, default=list)
    seeds: Mapped[Any] = mapped_column(JSON, default=list)
    severity_counts: Mapped[Any] = mapped_column(JSON, default=dict)
    owasp_coverage: Mapped[Any] = mapped_column(JSON, default=dict)
    matchups: Mapped[Any] = mapped_column(JSON, default=list)
    vulns: Mapped[list["Vulnerability"]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan",
        order_by="Vulnerability.rank")

    def to_dict(self) -> dict:
        return {
            "id": self.id, "tenant_id": self.tenant_id, "target": self.target,
            "label": self.label, "depth": self.depth, "status": self.status,
            "created_at": self.created_at, "runs": self.runs,
            "posture_grade": self.posture_grade,
            "mean_resilience": self.mean_resilience,
            "worst_resilience": self.worst_resilience,
            "best_resilience": self.best_resilience,
            "attacker_win_rate": self.attacker_win_rate,
            "scenarios": self.scenarios or [], "reds": self.reds or [],
            "blues": self.blues or [], "seeds": self.seeds or [],
            "severity_counts": self.severity_counts or {},
            "owasp_coverage": self.owasp_coverage or {},
            "matchups": self.matchups or [],
            "vulnerabilities": [v.to_dict() for v in self.vulns],
        }


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), index=True)
    rank: Mapped[int] = mapped_column(default=0)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(256))
    owasp: Mapped[str] = mapped_column(String(8), default="")
    owasp_title: Mapped[str] = mapped_column(String(128), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    cwe: Mapped[Any] = mapped_column(JSON, default=list)
    cvss_band: Mapped[str] = mapped_column(String(32), default="")
    risk_score: Mapped[float] = mapped_column(default=0.0)
    priority: Mapped[str] = mapped_column(String(4), default="P4")
    fix_sla_days: Mapped[int] = mapped_column(default=180)
    effort: Mapped[str] = mapped_column(String(4), default="M")
    mitigation: Mapped[str] = mapped_column(String(1024), default="")
    controls: Mapped[Any] = mapped_column(JSON, default=dict)
    occurrences: Mapped[int] = mapped_column(default=0)
    example_evidence: Mapped[str] = mapped_column(String(1024), default="")
    example_url: Mapped[str] = mapped_column(String(512), default="")
    campaign: Mapped[Campaign] = relationship(back_populates="vulns")

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "rule_id", "title", "owasp", "owasp_title", "severity", "cwe",
            "cvss_band", "risk_score", "priority", "fix_sla_days", "effort",
            "mitigation", "controls", "occurrences", "example_evidence",
            "example_url")}


class Engagement(Base):
    __tablename__ = "engagements"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    campaign_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    scenario: Mapped[str] = mapped_column(String(64), default="")
    seed: Mapped[int] = mapped_column(default=0)
    red: Mapped[str] = mapped_column(String(32), default="")
    blue: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(32), default="done")
    resilience: Mapped[int | None] = mapped_column(nullable=True)
    flag_captured: Mapped[bool | None] = mapped_column(nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), default=now_iso)
    finished_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifacts_dir: Mapped[str] = mapped_column(String(512), default="")

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in (
            "id", "tenant_id", "campaign_id", "scenario", "seed", "red", "blue",
            "status", "resilience", "flag_captured", "created_at", "finished_at",
            "artifacts_dir")}


class SqlStore(Store):
    def __init__(self, url: str) -> None:
        self.url = url
        kw: dict = {"future": True}
        if url.startswith("sqlite"):
            kw["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url or url in ("sqlite://", "sqlite:///:memory:"):
                kw["poolclass"] = StaticPool
        self.engine = create_engine(url, **kw)
        Base.metadata.create_all(self.engine)
        self._Session = sessionmaker(self.engine, expire_on_commit=False, future=True)
        self._lock = threading.Lock()

    # --- tenants --------------------------------------------------------
    def ensure_tenant(self, tenant_id: str, name: str | None = None) -> dict:
        with self._lock, self._Session() as s:
            t = s.get(Tenant, tenant_id)
            if t is None:
                t = Tenant(id=tenant_id, name=name or tenant_id)
                s.add(t)
                s.commit()
            return t.to_dict()

    def get_tenant(self, tenant_id: str) -> dict | None:
        with self._Session() as s:
            t = s.get(Tenant, tenant_id)
            return t.to_dict() if t else None

    def list_tenants(self) -> list[dict]:
        with self._Session() as s:
            return [t.to_dict() for t in s.scalars(select(Tenant)).all()]

    # --- targets --------------------------------------------------------
    def upsert_target(self, tenant_id: str, host: str, *, ownership_proven: bool,
                      proof_method: str | None = None,
                      proof_expires_at: str | None = None) -> dict:
        self.ensure_tenant(tenant_id)
        with self._lock, self._Session() as s:
            row = s.scalars(select(Target).where(
                Target.tenant_id == tenant_id, Target.host == host)).first()
            if row is None:
                row = Target(tenant_id=tenant_id, host=host)
                s.add(row)
            row.ownership_proven = ownership_proven
            row.proof_method = proof_method
            row.proof_expires_at = proof_expires_at
            row.updated_at = now_iso()
            s.commit()
            return row.to_dict()

    def get_target(self, tenant_id: str, host: str) -> dict | None:
        with self._Session() as s:
            row = s.scalars(select(Target).where(
                Target.tenant_id == tenant_id, Target.host == host)).first()
            return row.to_dict() if row else None

    def list_targets(self, tenant_id: str) -> list[dict]:
        with self._Session() as s:
            rows = s.scalars(select(Target).where(
                Target.tenant_id == tenant_id)).all()
            return [r.to_dict() for r in rows]

    # --- campaigns ------------------------------------------------------
    def save_campaign(self, record: dict) -> dict:
        self.ensure_tenant(record.get("tenant_id", DEFAULT_TENANT))
        with self._lock, self._Session() as s:
            c = s.get(Campaign, record["id"])
            if c is None:
                c = Campaign(id=record["id"])
                s.add(c)
            c.tenant_id = record.get("tenant_id", DEFAULT_TENANT)
            for k in ("target", "label", "depth", "status", "created_at", "runs",
                      "posture_grade", "mean_resilience", "worst_resilience",
                      "best_resilience", "attacker_win_rate", "scenarios", "reds",
                      "blues", "seeds", "severity_counts", "owasp_coverage",
                      "matchups"):
                if k in record and record[k] is not None:
                    setattr(c, k, record[k])
            c.vulns.clear()
            for i, v in enumerate(record.get("vulnerabilities", [])):
                c.vulns.append(Vulnerability(rank=i, **{
                    k: v.get(k) for k in (
                        "rule_id", "title", "owasp", "owasp_title", "severity",
                        "cwe", "cvss_band", "risk_score", "priority",
                        "fix_sla_days", "effort", "mitigation", "controls",
                        "occurrences", "example_evidence", "example_url")}))
            s.commit()
            return c.to_dict()

    def get_campaign(self, campaign_id: str) -> dict | None:
        with self._Session() as s:
            c = s.get(Campaign, campaign_id)
            return c.to_dict() if c else None

    def list_campaigns(self, tenant_id: str | None = None,
                       limit: int = 100) -> list[dict]:
        with self._Session() as s:
            q = select(Campaign)
            if tenant_id is not None:
                q = q.where(Campaign.tenant_id == tenant_id)
            q = q.order_by(Campaign.created_at.desc()).limit(limit)
            return [c.to_dict() for c in s.scalars(q).all()]

    # --- engagements ----------------------------------------------------
    def save_engagement(self, record: dict) -> dict:
        self.ensure_tenant(record.get("tenant_id", DEFAULT_TENANT))
        with self._lock, self._Session() as s:
            e = s.get(Engagement, record["id"])
            if e is None:
                e = Engagement(id=record["id"])
                s.add(e)
            for k in ("tenant_id", "campaign_id", "scenario", "seed", "red",
                      "blue", "status", "resilience", "flag_captured",
                      "created_at", "finished_at", "artifacts_dir"):
                if k in record:
                    setattr(e, k, record[k])
            s.commit()
            return e.to_dict()

    def get_engagement(self, engagement_id: str) -> dict | None:
        with self._Session() as s:
            e = s.get(Engagement, engagement_id)
            return e.to_dict() if e else None

    def list_engagements(self, tenant_id: str | None = None,
                         limit: int = 200) -> list[dict]:
        with self._Session() as s:
            q = select(Engagement)
            if tenant_id is not None:
                q = q.where(Engagement.tenant_id == tenant_id)
            q = q.order_by(Engagement.created_at.desc()).limit(limit)
            return [e.to_dict() for e in s.scalars(q).all()]

    def close(self) -> None:
        self.engine.dispose()
