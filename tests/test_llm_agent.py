"""LLM agents are tested with a fake client — no network, no API key.

Proves the agent turns model output into valid actions, respects the vocabulary
and the ≤3 cap, and survives malformed or failing model responses (the referee
remains the authority that drops anything invalid).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sentinel_arena.agents.llm import LLMBlue, LLMRed, _parse_actions
from sentinel_arena.authz import (
    AuditLog, AuthorizationGate, Environment, OwnershipVerifier, RateCap, Scope,
)
from sentinel_arena.detect.client import GatedHttpClient
from sentinel_arena.engine.actions import validate_action
from sentinel_arena.engine.context import EngagementContext
from sentinel_arena.scenarios.loader import load_scenario


class FakeLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls = 0

    def complete(self, system: str, user: str) -> str:
        self.calls += 1
        return self.response


def _ctx(tmp_path):
    scenario = load_scenario("shop-01")
    now = datetime.now(timezone.utc)
    scope = Scope(allowed_hosts=["127.0.0.1"], allowed_paths=["/"],
                  rate_cap=RateCap(max_requests=100, per_seconds=60),
                  environment=Environment.STAGING,
                  not_before=now - timedelta(minutes=1),
                  not_after=now + timedelta(hours=1))
    gate = AuthorizationGate(secret=b"x" * 16, verifier=OwnershipVerifier(),
                             audit=AuditLog(tmp_path / "a.jsonl"))
    from sentinel_arena.telemetry.events import EventStore
    events = EventStore(tmp_path / "e.jsonl")
    client = GatedHttpClient(gate=gate, user_id="u", host="127.0.0.1",
                             base_url="http://127.0.0.1:1", scope=scope)
    return EngagementContext(gate=gate, user_id="u", host="127.0.0.1", scope=scope,
                             scenario=scenario, randomized=scenario.randomized(1),
                             range=None, events=events, red_client=client)


def test_llm_red_parses_valid_actions(tmp_path):
    fake = FakeLLM('[{"kind":"recon","params":{},"rationale":"map"}]')
    agent = LLMRed(fake)
    actions = agent.propose(_ctx(tmp_path))
    assert len(actions) == 1 and actions[0].kind == "recon"
    for a in actions:
        validate_action(a)  # must pass the referee's gate


def test_llm_output_is_capped_at_three(tmp_path):
    fake = FakeLLM('[{"kind":"recon"},{"kind":"detect"},{"kind":"enumerate_paths"},'
                   '{"kind":"capture_flag"}]')
    actions = LLMRed(fake).propose(_ctx(tmp_path))
    assert len(actions) <= 3


def test_malformed_output_yields_no_actions(tmp_path):
    assert LLMRed(FakeLLM("I cannot help with that")).propose(_ctx(tmp_path)) == []
    assert _parse_actions("not json", "red") == []


def test_client_failure_is_survived(tmp_path):
    class Boom:
        def complete(self, s, u):
            raise RuntimeError("model down")
    assert LLMBlue(Boom()).propose(_ctx(tmp_path)) == []


def test_blue_can_emit_block_with_params(tmp_path):
    fake = FakeLLM('[{"kind":"query_logs"},{"kind":"block_ip","params":{"actor":"red"}}]')
    actions = LLMBlue(fake).propose(_ctx(tmp_path))
    kinds = {a.kind for a in actions}
    assert "block_ip" in kinds
    block = [a for a in actions if a.kind == "block_ip"][0]
    assert block.params.get("actor") == "red"
    for a in actions:
        validate_action(a)
