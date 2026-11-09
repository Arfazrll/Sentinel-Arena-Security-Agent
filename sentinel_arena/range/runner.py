"""Lifecycle control for the bundled range target.

This is the in-process, zero-dependency range (no Docker required) used for
local runs, demos, and CI. The brief's Docker-based range is a future swap-in
behind this same ``Range`` interface; the rest of the platform only depends on
``base_url`` + health, not on how the target is hosted.
"""

from __future__ import annotations

import time
import urllib.request
from dataclasses import dataclass

from ..scenarios.model import Randomized, Scenario
from .vulnerable_app import AppConfig, start_app


@dataclass
class Range:
    server: object
    base_url: str
    config: AppConfig
    host: str

    def health_ok(self, scenario: Scenario, timeout: float = 2.0) -> bool:
        url = f"{self.base_url}{scenario.health.path}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.status == scenario.health.expect_status
        except Exception:
            return False

    def block(self, actor: str) -> None:
        self.config.blocked_actors.add(actor)

    def unblock(self, actor: str) -> None:
        self.config.blocked_actors.discard(actor)

    def shutdown(self) -> None:
        try:
            self.server.shutdown()  # type: ignore[attr-defined]
            self.server.server_close()  # type: ignore[attr-defined]
        except Exception:
            pass


def bring_up(
    scenario: Scenario,
    randomized: Randomized,
    token: str,
    *,
    sink=None,
    tick_provider=None,
    host: str = "127.0.0.1",
) -> Range:
    """Start the range for a scenario and wait until it is healthy."""
    # Serve exactly the weaknesses this scenario declares, so different scenarios
    # produce genuinely different reports. The admin->flag discovery chain is
    # always served by the app regardless, so every scenario stays solvable.
    profile = {w.detect for w in scenario.weaknesses}
    config = AppConfig(
        token=token,
        flag_path=randomized.flag_path,
        admin_path=randomized.admin_path,
        flag_value=randomized.flag_value,
        credential=randomized.credential,
        weaknesses=profile or set(),
        sink=sink,
        tick_provider=tick_provider,
    )
    server, base_url, _thread = start_app(config, host=host)
    rng = Range(server=server, base_url=base_url, config=config, host=host)

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if rng.health_ok(scenario):
            return rng
        time.sleep(0.05)
    rng.shutdown()
    raise RuntimeError("range failed health check on startup")
