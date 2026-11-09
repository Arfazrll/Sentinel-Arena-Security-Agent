"""Standalone entrypoint to run the bundled vulnerable app in a container.

Reads its configuration from the environment so the Docker-backed range can
parameterize it (token, randomized paths, flag, control token). Binds to
0.0.0.0 inside the container; the container itself lives on an internal Docker
network with no route to the internet.

    python -m sentinel_arena.range.serve
"""

from __future__ import annotations

import os

from .vulnerable_app import AppConfig, start_app


def main() -> None:
    cfg = AppConfig(
        token=os.environ.get("ARENA_TOKEN", "dev-token"),
        flag_path=os.environ.get("ARENA_FLAG_PATH", "/files"),
        admin_path=os.environ.get("ARENA_ADMIN_PATH", "/admin"),
        flag_value=os.environ.get("ARENA_FLAG_VALUE", "FLAG{dev}"),
        credential=os.environ.get("ARENA_CREDENTIAL", "dev-cred"),
        control_token=os.environ.get("ARENA_CONTROL_TOKEN") or None,
    )
    port = int(os.environ.get("ARENA_PORT", "8080"))
    server, base_url, _ = start_app(cfg, host="0.0.0.0", port=port)
    print(f"sentinel-arena range listening on {base_url}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover
        server.shutdown()


if __name__ == "__main__":  # pragma: no cover
    main()
