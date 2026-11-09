"""Shared engagement context handed to agents and executors.

Bundles everything a turn needs: the gate + scope (so every action stays
authorized), the red team's gated client, the range, the event store, the
scenario, and the mutable shared state (findings, discovered paths, blue's
blocklist). Agents read/propose against this; the referee is the only thing that
executes and mutates authoritative state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..authz import AuthorizationGate, Scope
from ..detect.client import GatedHttpClient
from ..detect.findings import FindingList
from ..range.runner import Range
from ..scenarios.model import Randomized, Scenario
from ..telemetry.events import EventStore


@dataclass
class SharedState:
    """Mutable scratchpad shared within a team and across the engagement."""

    discovered_paths: set[str] = field(default_factory=set)
    discovered_admin_path: str | None = None
    discovered_flag_path: str | None = None
    findings: FindingList = field(default_factory=FindingList)
    flag_captured: bool = False
    recon_done: bool = False
    blocked_actors: set[str] = field(default_factory=set)
    detected_attackers: set[str] = field(default_factory=set)
    ticks_to_first_detection: int | None = None


@dataclass
class EngagementContext:
    gate: AuthorizationGate
    user_id: str
    host: str
    scope: Scope
    scenario: Scenario
    randomized: Randomized
    range: Range
    events: EventStore
    red_client: GatedHttpClient
    state: SharedState = field(default_factory=SharedState)
    tick: int = 0
    seed: int = 0
