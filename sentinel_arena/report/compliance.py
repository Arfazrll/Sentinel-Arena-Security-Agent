"""Map findings to the identifiers auditors and scanners speak.

For each finding we attach:

* a stable rule id (used for de-duplication across runs and in SARIF),
* CWE ids,
* indicative control references in NIST CSF 2.0, ISO/IEC 27001:2022 Annex A,
  PCI DSS v4.0 and the SOC 2 Trust Services Criteria,
* a CVSS v3 qualitative band for the severity, a remediation priority, and a
  rough effort estimate.

The control mapping is *indicative* - it tells a team where a finding most
likely lands in their framework, not a certified audit opinion.
"""

from __future__ import annotations

from ..detect.findings import OWASP_TOP_10

# Keyed by the finding title the detect checks emit.
RULES: dict[str, dict] = {
    "Missing security response headers": {
        "rule_id": "SA-HDR-001", "cwe": ["CWE-693", "CWE-1021"], "effort": "S",
        "nist_csf": ["PR.PS-01"], "iso27001": ["A.8.9"],
        "pci_dss": ["6.4.1", "2.2"], "soc2": ["CC7.1"],
    },
    "Reflected input without output encoding": {
        "rule_id": "SA-XSS-001", "cwe": ["CWE-79"], "effort": "M",
        "nist_csf": ["PR.PS-06"], "iso27001": ["A.8.28"],
        "pci_dss": ["6.2.4"], "soc2": ["CC8.1"],
    },
    "Admin panel reachable without authentication": {
        "rule_id": "SA-ACL-001", "cwe": ["CWE-306", "CWE-284"], "effort": "M",
        "nist_csf": ["PR.AA-05"], "iso27001": ["A.5.15", "A.8.5"],
        "pci_dss": ["7.2", "8.2"], "soc2": ["CC6.1"],
    },
    "Verbose server errors leak stack traces": {
        "rule_id": "SA-ERR-001", "cwe": ["CWE-209"], "effort": "S",
        "nist_csf": ["PR.PS-01"], "iso27001": ["A.8.28"],
        "pci_dss": ["6.2.4"], "soc2": ["CC7.1"],
    },
    "Sensitive config file exposed under web root": {
        "rule_id": "SA-EXP-001", "cwe": ["CWE-538", "CWE-200"], "effort": "S",
        "nist_csf": ["PR.DS-01"], "iso27001": ["A.8.12", "A.8.9"],
        "pci_dss": ["2.2", "8.3.2"], "soc2": ["CC6.1"],
    },
}

_OWASP_FALLBACK = {
    "A01": {"cwe": ["CWE-284"], "nist_csf": ["PR.AA-05"], "iso27001": ["A.5.15"],
            "pci_dss": ["7.2"], "soc2": ["CC6.1"]},
    "A03": {"cwe": ["CWE-74"], "nist_csf": ["PR.PS-06"], "iso27001": ["A.8.28"],
            "pci_dss": ["6.2.4"], "soc2": ["CC8.1"]},
    "A05": {"cwe": ["CWE-16"], "nist_csf": ["PR.PS-01"], "iso27001": ["A.8.9"],
            "pci_dss": ["2.2"], "soc2": ["CC7.1"]},
}

# CVSS v3.x qualitative severity bands + a representative score for sorting
# and for SARIF's "security-severity" property.
CVSS_BANDS = {
    "critical": ("9.0-10.0", 9.5),
    "high": ("7.0-8.9", 7.5),
    "medium": ("4.0-6.9", 5.3),
    "low": ("0.1-3.9", 3.1),
    "info": ("0.0", 0.0),
}

PRIORITY = {"critical": "P1", "high": "P1", "medium": "P2", "low": "P3", "info": "P4"}
SLA_DAYS = {"P1": 7, "P2": 30, "P3": 90, "P4": 180}

FRAMEWORKS = {
    "nist_csf": "NIST CSF 2.0",
    "iso27001": "ISO/IEC 27001:2022",
    "pci_dss": "PCI DSS v4.0",
    "soc2": "SOC 2 TSC",
}


def _slug(title: str) -> str:
    return "SA-" + "".join(c for c in title.upper() if c.isalnum())[:12]


def enrich(finding: dict) -> dict:
    """Return a copy of a finding dict with compliance + triage metadata."""
    sev = str(finding.get("severity", "info")).lower()
    owasp = finding.get("owasp", "")
    rule = RULES.get(finding.get("title", ""))
    base = dict(rule) if rule else {"rule_id": _slug(finding.get("title", "")),
                                    "effort": "M", **_OWASP_FALLBACK.get(owasp, {})}
    band, score = CVSS_BANDS.get(sev, CVSS_BANDS["info"])
    priority = PRIORITY.get(sev, "P4")
    return {
        **finding,
        "rule_id": base["rule_id"],
        "owasp_title": OWASP_TOP_10.get(owasp, "Uncategorized"),
        "cwe": base.get("cwe", []),
        "controls": {k: base.get(k, []) for k in FRAMEWORKS},
        "cvss_band": band,
        "risk_score": score,
        "priority": priority,
        "fix_sla_days": SLA_DAYS[priority],
        "effort": base.get("effort", "M"),
    }
