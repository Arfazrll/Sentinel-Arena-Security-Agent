"""Scenario schema + seeded randomizer.

A scenario is one YAML file describing a target with planted (benign)
weaknesses, a flag location, SLA health check, tick budget, and a list of
fields to randomize per engagement so models cannot win by memorization.

Validation is free because the schema is Pydantic.
"""

from __future__ import annotations

import random
import string
from pydantic import BaseModel, Field


class PlantedWeakness(BaseModel):
    """A weakness intentionally planted in the bundled app, for detection."""

    id: str
    owasp: str
    severity: str
    title: str
    detect: str  # which detect check keys this (e.g. "security_headers")
    mitigation: str


class HealthCheck(BaseModel):
    path: str = "/health"
    expect_status: int = 200


class Randomized(BaseModel):
    """Values regenerated per engagement from the seed."""

    flag_path: str
    admin_path: str
    flag_value: str
    credential: str


class Scenario(BaseModel):
    id: str
    name: str
    description: str = ""
    max_ticks: int = Field(default=12, gt=0)
    health: HealthCheck = Field(default_factory=HealthCheck)
    weaknesses: list[PlantedWeakness] = Field(default_factory=list)
    # Template values; the randomizer overrides the fields listed in `randomize`.
    flag_path: str = "/files"
    admin_path: str = "/admin"
    randomize: list[str] = Field(default_factory=list)

    def randomized(self, seed: int) -> Randomized:
        """Deterministically derive the per-engagement randomized values."""
        rng = random.Random(seed)

        def token(n: int) -> str:
            return "".join(rng.choice(string.ascii_lowercase) for _ in range(n))

        flag_path = self.flag_path
        admin_path = self.admin_path
        if "flag_path" in self.randomize:
            flag_path = f"/{token(8)}"
        if "admin_path" in self.randomize:
            admin_path = f"/{token(6)}-admin"
        flag_value = "FLAG{" + "".join(rng.choice(string.hexdigits.lower()) for _ in range(16)) + "}"
        credential = token(12)
        return Randomized(
            flag_path=flag_path,
            admin_path=admin_path,
            flag_value=flag_value,
            credential=credential,
        )
