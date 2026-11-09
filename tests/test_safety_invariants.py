"""Safety-invariant regression gate.

These tests encode the non-negotiable invariants (brief §1). If a refactor
removes or weakens one, CI fails here. This is the mechanism the brief's
definition of done requires: "CI fails if any safety invariant is removed."
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel_arena.authz import (
    AuditLog,
    AuthorizationGate,
    Environment,
    OwnershipVerifier,
    RateCap,
    Scope,
)
from sentinel_arena.authz.errors import OwnershipNotProven
from sentinel_arena.engine.actions import BLUE_ACTIONS, RED_ACTIONS

REPO = Path(__file__).parents[1]

DESTRUCTIVE_VERBS = {"exploit", "ddos", "dos", "deface", "exfiltrate", "bruteforce",
                     "shell", "rce", "wipe", "destroy"}


def test_safety_doc_lists_all_seven_invariants():
    text = (REPO / "docs" / "SAFETY.md").read_text(encoding="utf-8")
    numbered = re.findall(r"^\s*(\d+)\.\s+\*\*", text, flags=re.MULTILINE)
    assert {str(i) for i in range(1, 8)}.issubset(set(numbered)), \
        "SAFETY.md must enumerate invariants 1..7"


def test_blue_has_no_free_shell():
    assert "run_shell" not in BLUE_ACTIONS
    for action in BLUE_ACTIONS:
        assert not any(v in action for v in DESTRUCTIVE_VERBS)


def test_red_vocabulary_is_non_destructive():
    for action in RED_ACTIONS:
        assert not any(v in action for v in DESTRUCTIVE_VERBS)


def test_gate_blocks_until_ownership_proven(tmp_path):
    """Invariant #1 + #4: the target is inert until the gate passes."""
    now = datetime.now(timezone.utc)
    scope = Scope(allowed_hosts=["example.com"], allowed_paths=["/"],
                  rate_cap=RateCap(max_requests=10, per_seconds=60),
                  environment=Environment.STAGING,
                  not_before=now - timedelta(minutes=1),
                  not_after=now + timedelta(hours=1))
    gate = AuthorizationGate(secret=b"x" * 16,
                             verifier=OwnershipVerifier(),
                             audit=AuditLog(tmp_path / "a.jsonl"))
    with pytest.raises(OwnershipNotProven):
        gate.check("user", "example.com", "/", scope)
