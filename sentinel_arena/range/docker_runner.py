"""Docker-backed range — the same ``Range`` surface, hosted in a container.

Drop-in alternative to the in-process range. It builds/starts the bundled app
in a container on an **internal Docker network with no internet route**, maps a
port to the host, verifies health, and toggles the blocklist over the app's
token-gated control endpoint (never via docker.sock, which is never mounted).

Requires Docker and the Docker SDK for Python (`pip install docker`). It is not
exercised by the offline test suite (CI has no Docker); the in-process range is
the tested default. This class exists so a single-node demo host can run the
range in a container without changing the engine, detection, or agents.

Safety notes honoring the brief:
  * internal network only, no internet (`internal=True`);
  * docker.sock is never mounted into the container;
  * per-container CPU/memory caps;
  * the container is always torn down on shutdown.
"""

from __future__ import annotations

import secrets
import time
import urllib.request
from dataclasses import dataclass

from ..scenarios.model import Randomized, Scenario
from .runner import Range  # reuse the same dataclass surface


IMAGE_TAG = "sentinel-arena-range:latest"
NETWORK_NAME = "sentinel-arena-internal"


@dataclass
class DockerRange:
    """Mirrors ``range.runner.Range`` but backed by a container.

    Implements the same methods the engine depends on: ``health_ok``,
    ``block``, ``unblock``, ``shutdown`` plus a ``base_url`` attribute.
    """

    container: object
    network: object
    base_url: str
    host: str
    control_token: str

    def health_ok(self, scenario: Scenario, timeout: float = 2.0) -> bool:
        url = f"{self.base_url}{scenario.health.path}"
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return resp.status == scenario.health.expect_status
        except Exception:
            return False

    def _control(self, action: str, actor: str) -> None:
        url = f"{self.base_url}/__arena/{action}?actor={actor}"
        req = urllib.request.Request(url, headers={"X-Arena-Control": self.control_token})
        try:
            urllib.request.urlopen(req, timeout=2.0).read()
        except Exception:
            pass

    def block(self, actor: str) -> None:
        self._control("block", actor)

    def unblock(self, actor: str) -> None:
        self._control("unblock", actor)

    def shutdown(self) -> None:
        try:
            self.container.stop(timeout=3)
        except Exception:
            pass
        try:
            self.container.remove(force=True)
        except Exception:
            pass
        try:
            self.network.remove()
        except Exception:
            pass


def bring_up_docker(
    scenario: Scenario,
    randomized: Randomized,
    token: str,
    *,
    host: str = "127.0.0.1",
    build: bool = True,
    mem_limit: str = "256m",
    nano_cpus: int = 1_000_000_000,  # 1 CPU
) -> DockerRange:
    """Build (optionally) and start the range container. Requires Docker."""
    try:
        import docker  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Docker-backed range needs the Docker SDK: pip install docker"
        ) from e

    client = docker.from_env()
    control_token = secrets.token_hex(16)

    if build:
        # Build context is the repo root (two levels up from this file).
        import pathlib
        repo_root = pathlib.Path(__file__).resolve().parents[2]
        client.images.build(path=str(repo_root),
                            dockerfile="sentinel_arena/range/Dockerfile",
                            tag=IMAGE_TAG, rm=True)

    # Internal network: no route to the internet.
    try:
        network = client.networks.create(NETWORK_NAME, driver="bridge", internal=True)
    except Exception:
        network = client.networks.get(NETWORK_NAME)

    container = client.containers.run(
        IMAGE_TAG,
        detach=True,
        remove=False,
        network=network.name,
        ports={"8080/tcp": ("127.0.0.1", None)},  # ephemeral host port on loopback
        environment={
            "ARENA_TOKEN": token,
            "ARENA_FLAG_PATH": randomized.flag_path,
            "ARENA_ADMIN_PATH": randomized.admin_path,
            "ARENA_FLAG_VALUE": randomized.flag_value,
            "ARENA_CREDENTIAL": randomized.credential,
            "ARENA_CONTROL_TOKEN": control_token,
        },
        mem_limit=mem_limit,
        nano_cpus=nano_cpus,
        # docker.sock is deliberately NOT mounted.
    )

    # Discover the mapped host port.
    container.reload()
    port_info = container.attrs["NetworkSettings"]["Ports"]["8080/tcp"][0]
    base_url = f"http://{host}:{port_info['HostPort']}"

    rng = DockerRange(container=container, network=network, base_url=base_url,
                      host=host, control_token=control_token)

    deadline = time.time() + 20.0
    while time.time() < deadline:
        if rng.health_ok(scenario):
            return rng
        time.sleep(0.2)
    rng.shutdown()
    raise RuntimeError("docker range failed health check on startup")
