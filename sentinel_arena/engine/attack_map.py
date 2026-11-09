"""Map engagement actions to MITRE ATT&CK techniques.

A deliberately small, static mapping — enough to tag each action in the report
and timeline. Keyed by the action's ``kind``.
"""

from __future__ import annotations

from pydantic import BaseModel


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str


# action kind -> ATT&CK technique
ATTACK_MAP: dict[str, AttackTechnique] = {
    "recon": AttackTechnique(technique_id="T1595", name="Active Scanning",
                             tactic="Reconnaissance"),
    "enumerate_paths": AttackTechnique(technique_id="T1595.003",
                                       name="Wordlist Scanning",
                                       tactic="Reconnaissance"),
    "detect": AttackTechnique(technique_id="T1190",
                              name="Exploit Public-Facing Application (detect)",
                              tactic="Initial Access"),
    "capture_flag": AttackTechnique(technique_id="T1083",
                                    name="File and Directory Discovery",
                                    tactic="Discovery"),
    # Blue techniques (defensive, framed as ATT&CK coverage of the attacker).
    "query_logs": AttackTechnique(technique_id="DS0015", name="Application Log",
                                  tactic="Detection"),
    "block_ip": AttackTechnique(technique_id="M1037", name="Filter Network Traffic",
                                tactic="Mitigation"),
    "isolate_host": AttackTechnique(technique_id="M1030", name="Network Segmentation",
                                    tactic="Mitigation"),
}


def technique_for(kind: str) -> AttackTechnique | None:
    return ATTACK_MAP.get(kind)
