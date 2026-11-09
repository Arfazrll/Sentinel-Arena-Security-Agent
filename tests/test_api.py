"""API routes, called directly (the env's TestClient dependency is unavailable).
Skipped when the optional ``api`` extra is not installed."""

from __future__ import annotations

import time

import pytest

server = pytest.importorskip("sentinel_arena.api.server")
from fastapi import HTTPException  # noqa: E402


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ENG_ROOT", tmp_path / "engagements")
    monkeypatch.setattr(server, "BENCH_FILE", tmp_path / "bench" / "latest.json")
    monkeypatch.setattr(server, "_ENGAGEMENTS", {})
    monkeypatch.setattr(server, "_BENCHMARKS", {})


def _wait(eid: str, timeout: float = 30) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = server.engagement_status(eid)
        if st["status"] != "running":
            return st
        time.sleep(0.1)
    raise AssertionError("engagement did not finish")


def test_rejects_unknown_agents_and_scenarios():
    for kw in ({"red": "nope"}, {"blue": "nope"}, {"scenario": "nope"}):
        with pytest.raises(HTTPException) as e:
            server.start_engagement(**{"scenario": "shop-01", "seed": 1,
                                       "red": "scripted", "blue": "scripted",
                                       "pace_ms": 0, **kw})
        assert e.value.status_code == 400


def test_full_engagement_lifecycle_and_exports():
    eid = server.start_engagement(scenario="shop-01", seed=7, red="scripted",
                                  blue="noop", pace_ms=0)["id"]
    st = _wait(eid)
    assert st["status"] == "done" and st["result"]["flag_captured"]
    assert st["findings"] > 0 and st["red_label"] == "Methodical"

    assert server.list_engagements(limit=10)["total"] == 1
    assert server.engagement_result(eid)["kpis"]
    assert server.engagement_events(eid)["events"]
    audit = server.engagement_audit(eid, limit=10)
    assert audit["verified"] is True and audit["total"] > 0
    for fmt in ("sarif", "navigator", "csv", "json", "md"):
        assert server.export(eid, fmt).status_code == 200
    with pytest.raises(HTTPException):
        server.export(eid, "exe")
    agg = server.findings()
    assert agg["total"] > 0 and agg["findings"][0]["occurrences"] == 1


def test_stop_trips_the_kill_switch():
    eid = server.start_engagement(scenario="shop-01", seed=42, red="scripted",
                                  blue="scripted", pace_ms=2000)["id"]
    time.sleep(0.3)
    assert server.stop_engagement(eid, reason="test")["stopped"] is True
    st = _wait(eid)
    assert st["status"] == "stopped"
    assert st["result"]["ended"] == "killswitch: test"


def test_history_reloads_from_disk():
    eid = server.start_engagement(scenario="shop-01", seed=1, red="scripted",
                                  blue="scripted", pace_ms=0)["id"]
    _wait(eid)
    server._ENGAGEMENTS.clear()
    server._load_history()
    assert eid in server._ENGAGEMENTS
    assert server.engagement_status(eid)["status"] == "done"
