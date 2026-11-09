"""MCP surface: the server builds and exposes exactly the orchestration/reporting
tools - and no attack primitive."""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("mcp")  # the MCP SDK is an optional extra


def _tool_names():
    from sentinel_arena.mcp.server import build_server

    server = build_server()
    tools = asyncio.new_event_loop().run_until_complete(server.list_tools())
    return {t.name for t in tools}


def test_server_exposes_expected_tools():
    names = _tool_names()
    assert names == {"list_scenarios", "list_agents", "verify_target", "run_assessment"}


def test_no_raw_attack_tool_is_exposed():
    # Guardrail: the MCP surface must never expose a direct "attack this host"
    # primitive. Everything is orchestration (assessment) or reporting.
    names = _tool_names()
    forbidden = {"exploit", "attack", "capture_flag", "send_payload", "shell", "recon"}
    assert not (names & forbidden)
