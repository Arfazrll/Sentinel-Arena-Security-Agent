"""Findings, severity, and the OWASP Top 10 (2021) catalog.

A :class:`Finding` is the unit of the resilience audit: a detected weakness,
mapped to an OWASP category, with a severity and a recommended mitigation.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            "info": 1, "low": 2, "medium": 4, "high": 7, "critical": 10,
        }[self.value]


# OWASP Top 10 (2021) — code -> human title.
OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


class Finding(BaseModel):
    id: str
    title: str
    owasp: str  # e.g. "A05"
    severity: Severity
    description: str
    evidence: str
    mitigation: str
    url: str = ""
    tick: int = -1

    @property
    def owasp_title(self) -> str:
        return OWASP_TOP_10.get(self.owasp, "Uncategorized")

    def label(self) -> str:
        return f"{self.owasp} {self.owasp_title}"


class FindingList(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

    def add(self, f: Finding) -> None:
        # De-duplicate by (title, url) so repeated checks don't inflate the report.
        key = (f.title, f.url)
        if not any((g.title, g.url) == key for g in self.findings):
            self.findings.append(f)

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def owasp_coverage(self) -> dict[str, list[Finding]]:
        cov: dict[str, list[Finding]] = {}
        for f in self.findings:
            cov.setdefault(f.owasp, []).append(f)
        return cov
