"""Benign background traffic generator.

Simulates ordinary users hitting the storefront during the engagement. This is
environment noise — not a platform action — so it talks to the range directly.
Its purpose is to give the blue team something to *not* block: a defender that
blindly blocks everyone will knock these legitimate users offline and lose
points for it.
"""

from __future__ import annotations

import urllib.request

LEGIT_ACTORS = ["legit-1", "legit-2"]
LEGIT_PATHS = ["/", "/search?q=socks", "/health"]


class BenignTraffic:
    def __init__(self, actors=None, paths=None) -> None:
        self.actors = actors or LEGIT_ACTORS
        self.paths = paths or LEGIT_PATHS

    def generate(self, rng, tick: int = -1) -> None:
        for actor in self.actors:
            for path in self.paths:
                url = f"{rng.base_url}{path}"
                req = urllib.request.Request(url, headers={"X-Arena-Actor": actor})
                try:
                    urllib.request.urlopen(req, timeout=2.0).read()
                except Exception:
                    pass  # a blocked legit user (403) is recorded by the app sink
