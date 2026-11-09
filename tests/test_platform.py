"""Platform features layered on the engine: registry, KPIs, compliance
enrichment, exports, live pacing + kill switch, and the per-tick timeline."""

from __future__ import annotations

import json
import threading

import pytest

from sentinel_arena.agents import registry
from sentinel_arena.engagement import run_engagement
from sentinel_arena.engine.actions import BLUE_ACTIONS, RED_ACTIONS
from sentinel_arena.engine.killswitch import KillSwitch
from sentinel_arena.report.compliance import enrich
from sentinel_arena.report.exports import to_csv, to_navigator_layer, to_sarif


def _result(art) -> dict:
    return json.loads((art.out_dir / "result.json").read_text(encoding="utf-8"))


def _events(art) -> list[dict]:
    return [json.loads(line) for line in
            art.events_path.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="module")
def noop_run(tmp_path_factory):
    return run_engagement("shop-01", seed=7, blue_name="noop",
                          out_dir=tmp_path_factory.mktemp("noop"),
                          generate_report=False)


@pytest.fixture(scope="module")
def defended_run(tmp_path_factory):
    return run_engagement("shop-01", seed=7, out_dir=tmp_path_factory.mktemp("def"),
                          generate_report=False)


def test_registry_resolves_every_agent_and_rejects_unknown():
    for team, table in (("red", registry.RED), ("blue", registry.BLUE)):
        for name, spec in table.items():
            assert registry.get(team, name) is spec
            assert spec.team == team
    with pytest.raises(KeyError):
        registry.get("red", "does-not-exist")
    # LLM agents need a key, so they are not part of the default benchmark.
    assert "llm" not in registry.benchmark_names("red")
    assert {"scripted", "rush"} <= set(registry.benchmark_names("red"))


@pytest.mark.parametrize("name", ["rush"])
def test_new_red_agents_only_propose_vetted_actions(name, tmp_path):
    art = run_engagement("shop-01", seed=3, red_name=name, blue_name="noop",
                         out_dir=tmp_path, generate_report=False)
    kinds = {e["data"]["kind"] for e in _events(art)
             if e["kind"] == "action" and e["team"] == "red"}
    assert kinds and kinds <= RED_ACTIONS


@pytest.mark.parametrize("name", ["sweeper", "paranoid"])
def test_new_blue_agents_stay_inside_the_whitelist(name, tmp_path):
    art = run_engagement("shop-01", seed=3, blue_name=name, out_dir=tmp_path,
                         generate_report=False)
    kinds = {e["data"]["kind"] for e in _events(art)
             if e["kind"] == "action" and e["team"] == "blue"}
    assert kinds <= BLUE_ACTIONS


def test_paranoid_defender_is_penalized_for_false_blocks(tmp_path):
    good = run_engagement("shop-01", seed=3, out_dir=tmp_path / "a",
                          generate_report=False).result.scoreboard
    bad = run_engagement("shop-01", seed=3, blue_name="paranoid",
                         out_dir=tmp_path / "b", generate_report=False).result.scoreboard
    assert bad.blue.false_blocks > 0
    assert bad.resilience < good.resilience


def test_rush_attacker_beats_a_reactive_defender(tmp_path):
    art = run_engagement("shop-01", seed=3, red_name="rush", out_dir=tmp_path,
                         generate_report=False)
    assert art.result.scoreboard.red.flag_captured


def test_requests_are_tagged_with_the_current_tick(noop_run):
    ticks = [e["tick"] for e in _events(noop_run)
             if e["kind"] == "request" and e["actor"] == "red"]
    assert ticks and all(t >= 0 for t in ticks)


def test_result_has_meta_kpis_and_timeline(noop_run, defended_run):
    res = _result(noop_run)
    assert res["meta"]["red"] == "scripted" and res["meta"]["blue"] == "noop"
    assert res["meta"]["environment"] == "staging"
    assert len(res["timeline"]) == res["ticks_run"]
    assert res["kpis"]["time_to_detect"] is None  # nobody was watching

    d = _result(defended_run)
    assert d["kpis"]["time_to_detect"] is not None
    assert d["kpis"]["contain_tick"] is not None
    assert d["kpis"]["attacker_block_rate"] > 0
    assert d["timeline"][-1]["resilience"] == d["scoreboard"]["resilience"]


def test_action_events_carry_rationale(noop_run):
    acts = [e for e in _events(noop_run) if e["kind"] == "action"]
    assert acts and all(e["data"].get("rationale") for e in acts)


def test_findings_are_enriched_with_compliance(noop_run):
    findings = _result(noop_run)["findings"]
    assert findings
    for f in findings:
        assert f["rule_id"].startswith("SA-")
        assert f["cwe"] and f["priority"] in {"P1", "P2", "P3", "P4"}
        assert set(f["controls"]) == {"nist_csf", "iso27001", "pci_dss", "soc2"}
    xss = next(f for f in findings if f["owasp"] == "A03")
    assert "CWE-79" in xss["cwe"]


def test_enrich_falls_back_for_unknown_titles():
    f = enrich({"title": "Something new", "owasp": "A01", "severity": "high"})
    assert f["cwe"] == ["CWE-284"] and f["priority"] == "P1"


def test_sarif_navigator_and_csv_exports(noop_run):
    res = _result(noop_run)
    sarif = to_sarif(res)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert len(run["results"]) == len(res["findings"])
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert all(r["ruleId"] in rule_ids for r in run["results"])

    layer = to_navigator_layer(res, _events(noop_run))
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids and all(i.startswith("T") for i in ids)  # no DS/M ids leak in

    csv_text = to_csv(res)
    assert csv_text.splitlines()[0].startswith("rule_id,priority,severity")
    assert len(csv_text.strip().splitlines()) == len(res["findings"]) + 1


def test_kill_switch_interrupts_a_paced_run(tmp_path):
    kill = KillSwitch()
    threading.Timer(0.4, kill.trip, args=("test stop",)).start()
    art = run_engagement("shop-01", seed=42, out_dir=tmp_path, killswitch=kill,
                         tick_delay_s=2.0, generate_report=False)
    assert art.result.ended_reason == "killswitch: test stop"
    assert art.result.ticks_run <= 2
