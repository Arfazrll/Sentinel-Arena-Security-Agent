"""Machine-readable exports of an engagement.

* SARIF 2.1.0 - the format GitHub code scanning, Azure DevOps and most
  security dashboards ingest.
* MITRE ATT&CK Navigator layer - the red team's techniques, scored by use, to
  open at https://mitre-attack.github.io/attack-navigator/.
* CSV - findings for spreadsheets and ticket imports.

All of these are pure transforms over ``result.json`` and ``events.jsonl``.
"""

from __future__ import annotations

import csv
import io
from collections import Counter

from .. import __version__
from .compliance import FRAMEWORKS

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(result: dict) -> dict:
    findings = result.get("findings", [])
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rid = f.get("rule_id") or f.get("id")
        if rid not in rules:
            tags = ["security", f"OWASP-{f.get('owasp', '')}", *f.get("cwe", [])]
            rules[rid] = {
                "id": rid,
                "name": "".join(w.capitalize() for w in f.get("title", "").split()),
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("mitigation", "")},
                "properties": {
                    "tags": tags,
                    "security-severity": str(f.get("risk_score", 0.0)),
                },
            }
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity", "info"), "note"),
            "message": {"text": f"{f.get('title', '')}. Evidence: {f.get('evidence', '')}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("url") or "unknown"}}}],
            "properties": {"tick": f.get("tick", -1), "priority": f.get("priority")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Sentinel Arena",
                "version": __version__,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "scenario": result.get("scenario"),
                "seed": result.get("seed"),
                "resilience": result.get("scoreboard", {}).get("resilience"),
            },
        }],
    }


def to_navigator_layer(result: dict, events: list[dict]) -> dict:
    """ATT&CK Navigator layer of the red team's techniques (Enterprise)."""
    uses: Counter = Counter()
    names: dict[str, str] = {}
    for e in events:
        if e.get("kind") != "action" or e.get("team") != "red":
            continue
        tid = (e.get("data") or {}).get("attack_technique")
        if tid and tid.startswith("T"):
            uses[tid] += 1
            names[tid] = (e.get("data") or {}).get("technique_name") or tid
    top = max(uses.values(), default=1)
    meta = result.get("meta", {})
    return {
        "name": f"Sentinel Arena - {result.get('scenario')} seed {result.get('seed')}",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Red agent '{meta.get('red', 'scripted')}' vs blue agent "
                        f"'{meta.get('blue', 'scripted')}'. Score = times used."),
        "techniques": [
            {"techniqueID": tid, "score": n, "comment": f"{names[tid]} - used {n}x",
             "enabled": True}
            for tid, n in sorted(uses.items())
        ],
        "gradient": {"colors": ["#fde7e7", "#e34948"], "minValue": 0, "maxValue": top},
        "legendItems": [],
        "showTacticRowBackground": True,
    }


def to_csv(result: dict) -> str:
    buf = io.StringIO()
    cols = ["rule_id", "priority", "severity", "cvss_band", "owasp", "owasp_title",
            "title", "cwe", *FRAMEWORKS.keys(), "url", "tick", "evidence",
            "mitigation", "fix_sla_days", "effort"]
    w = csv.writer(buf)
    w.writerow(cols)
    for f in result.get("findings", []):
        controls = f.get("controls", {})
        row = []
        for c in cols:
            if c == "cwe":
                row.append(" ".join(f.get("cwe", [])))
            elif c in FRAMEWORKS:
                row.append(" ".join(controls.get(c, [])))
            else:
                row.append(f.get(c, ""))
        w.writerow(row)
    return buf.getvalue()
