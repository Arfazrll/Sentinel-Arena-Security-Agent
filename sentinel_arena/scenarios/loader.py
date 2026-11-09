"""Load and validate scenario YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from .model import Scenario

SCENARIOS_DIR = Path(__file__).parent


def load_scenario(scenario_id: str) -> Scenario:
    """Load ``scenarios/<id>/scenario.yaml`` and validate it."""
    path = SCENARIOS_DIR / scenario_id / "scenario.yaml"
    if not path.exists():
        raise FileNotFoundError(f"no scenario {scenario_id!r} at {path}")
    return load_scenario_file(path)


def load_scenario_file(path: str | Path) -> Scenario:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return Scenario.model_validate(data)


def list_scenarios() -> list[str]:
    out = []
    for child in SCENARIOS_DIR.iterdir():
        if child.is_dir() and (child / "scenario.yaml").exists():
            out.append(child.name)
    return sorted(out)
