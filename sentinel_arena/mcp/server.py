"""Sentinel Arena MCP server.

Run it:

    uv pip install -e ".[mcp]"
    python -m sentinel_arena.mcp.server         # stdio transport

Then point any MCP client at that command. Tools exposed:

* ``list_scenarios``   - the scenario library.
* ``list_agents``      - registered attacker / defender agents.
* ``verify_target``    - issue an ownership challenge for a host (step 1 of
  assessing a site you own: publish the returned DNS TXT / well-known file).
* ``run_assessment``   - run a campaign and return the prioritized
  vulnerabilities-and-mitigations verdict. Sandbox by default; a non-sandbox
  target is refused unless ``i_own_this=True`` (ownership proven out of band).

Design rule: this surface orchestrates and reports. It never ships an attack
step, and it cannot make the platform act against a host the gate has not
cleared.
"""

from __future__ import annotations

import os
import secrets as _secrets
from typing import Any

# --- resilient import across mcp 1.x (FastMCP) and 2.x (MCPServer) ----------
try:  # mcp >= 2.0
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:  # pragma: no cover - depends on installed version
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore

from ..agents.registry import all_agents
from ..authz import make_challenge
from ..campaign import CampaignPlan, run_campaign, to_markdown
from ..scenarios.loader import list_scenarios, load_scenario

SERVER_NAME = "sentinel-arena"
_USER = os.environ.get("ARENA_MCP_USER", "mcp-operator")


def _gate_secret() -> bytes:
    """Stable per-deployment secret for verification tokens. From the env in
    production (a vault); a random one otherwise (tokens stay valid for the life
    of the process)."""
    env = os.environ.get("ARENA_GATE_SECRET")
    if env:
        return env.encode("utf-8")
    globals().setdefault("_EPHEMERAL_SECRET", _secrets.token_bytes(32))
    return globals()["_EPHEMERAL_SECRET"]


def build_server() -> Any:
    server = _Server(SERVER_NAME)

    @server.tool(name="list_scenarios",
                 description="List the scenario library (each is a target "
                 "profile with planted, non-destructive weaknesses).")
    def list_scenarios_tool() -> list[dict]:
        out = []
        for sid in list_scenarios():
            sc = load_scenario(sid)
            out.append({"id": sc.id, "name": sc.name,
                        "description": sc.description.strip(),
                        "weaknesses": len(sc.weaknesses)})
        return out

    @server.tool(name="list_agents",
                 description="List registered attacker (red) and defender "
                 "(blue) agents and what each one does.")
    def list_agents_tool() -> list[dict]:
        return all_agents()

    @server.tool(description="Issue an ownership-verification challenge for a "
                 "host. Returns the DNS TXT record, well-known file and meta tag "
                 "to publish. Assessing a site you own starts here - this runs "
                 "nothing against the host, it only tells you how to prove it.")
    def verify_target(host: str, user_id: str = _USER) -> dict:
        ch = make_challenge(user_id, host, secret=_gate_secret())
        return {
            "host": ch.host,
            "user_id": ch.user_id,
            "token": ch.token,
            "methods": {
                "dns_txt": {"name": ch.dns_txt_name, "value": ch.dns_txt_value},
                "well_known_file": {"url": ch.well_known_url, "body": ch.well_known_body},
                "meta_tag": ch.meta_tag,
            },
            "next_step": "Publish any one of the above, then run_assessment with "
                         "i_own_this=true. Live verification of the published "
                         "proof is performed by the authorization gate before any "
                         "action is taken.",
        }

    @server.tool(description="Run a security assessment campaign and return the "
                 "prioritized vulnerabilities-and-mitigations verdict. depth is "
                 "quick|standard|deep. Sandbox target by default; a non-sandbox "
                 "target requires i_own_this=true (ownership proven already).")
    def run_assessment(
        target: str = "127.0.0.1",
        depth: str = "quick",
        scenarios: list[str] | None = None,
        label: str = "",
        i_own_this: bool = False,
    ) -> dict:
        plan = CampaignPlan(
            target=target, depth=depth, scenarios=scenarios or [],
            label=label, ownership_proven=i_own_this,
        )
        res = run_campaign(plan)
        data = res.model_dump()
        data["summary_markdown"] = to_markdown(res)
        data["headline"] = res.headline()
        return data

    return server


def main() -> None:
    build_server().run("stdio")


if __name__ == "__main__":
    main()
