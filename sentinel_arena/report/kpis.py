"""SOC-style KPIs derived from an engagement's event log.

All times are in ticks (the referee's unit of time), so runs compare fairly
regardless of machine speed.

* time_to_detect  - first attacker-only request -> blue first flags the attacker
* time_to_contain - blue first flags the attacker -> attacker is blocked
* dwell_ticks     - attacker's first action -> containment (or end of run)
"""

from __future__ import annotations

from collections import Counter

from ..engine.referee import MALICIOUS_MARKERS


def compute_kpis(events: list[dict], ticks_run: int) -> dict:
    first_red_tick = None
    first_malicious_tick = None
    detect_tick = None
    contain_tick = None
    red_actions = red_ok = blue_actions = blue_ok = rejected = 0
    techniques: dict[str, dict] = {}
    req = Counter()
    sla_fail_ticks = 0
    per_tick: dict[int, Counter] = {}

    for e in events:
        kind, team, tick = e.get("kind"), e.get("team"), e.get("tick", -1)
        data = e.get("data") or {}
        if kind == "request":
            actor = e.get("actor", "")
            blocked = data.get("marker") == "blocked"
            group = ("red" if actor == "red" else
                     "legit" if actor.startswith("legit") else "system")
            req[f"{group}_total"] += 1
            if blocked:
                req[f"{group}_blocked"] += 1
            if tick >= 0:
                per_tick.setdefault(tick, Counter())[
                    f"{group}_{'blocked' if blocked else 'ok'}"] += 1
            if (actor == "red" and data.get("marker") in MALICIOUS_MARKERS
                    and tick >= 0 and first_malicious_tick is None):
                first_malicious_tick = tick
        elif kind == "action":
            if team == "red":
                red_actions += 1
                red_ok += bool(data.get("ok"))
                if first_red_tick is None:
                    first_red_tick = tick
                tid = data.get("attack_technique")
                if tid:
                    t = techniques.setdefault(tid, {
                        "id": tid, "name": data.get("technique_name") or tid,
                        "tactic": data.get("tactic"), "uses": 0, "first_tick": tick,
                        "succeeded": 0})
                    t["uses"] += 1
                    t["succeeded"] += bool(data.get("ok"))
            elif team == "blue":
                blue_actions += 1
                blue_ok += bool(data.get("ok"))
                if (data.get("kind") == "query_logs" and "red" in
                        (data.get("suspects") or []) and detect_tick is None):
                    detect_tick = tick
                if (data.get("kind") in {"block_ip", "isolate_host"} and data.get("ok")
                        and contain_tick is None
                        and (data.get("actor") == "red" or data.get("kind") == "isolate_host")):
                    contain_tick = tick
        elif kind == "rejected":
            rejected += 1
        elif kind == "score_tick" and not data.get("sla_ok", True):
            sla_fail_ticks += 1

    def _gap(a, b):
        return None if a is None or b is None else max(0, b - a)

    start = first_malicious_tick if first_malicious_tick is not None else first_red_tick
    dwell = (_gap(first_red_tick, contain_tick) if contain_tick is not None
             else (ticks_run - (first_red_tick or 0)) if first_red_tick is not None
             else 0)
    return {
        "first_red_tick": first_red_tick,
        "first_malicious_tick": first_malicious_tick,
        "detect_tick": detect_tick,
        "contain_tick": contain_tick,
        "time_to_detect": _gap(start, detect_tick),
        "time_to_contain": _gap(detect_tick, contain_tick),
        "dwell_ticks": dwell,
        "red_actions": red_actions,
        "red_success_rate": round(red_ok / red_actions, 3) if red_actions else 0.0,
        "blue_actions": blue_actions,
        "blue_success_rate": round(blue_ok / blue_actions, 3) if blue_actions else 0.0,
        "rejected_actions": rejected,
        "requests": dict(req),
        "attacker_block_rate": (round(req["red_blocked"] / req["red_total"], 3)
                                if req["red_total"] else 0.0),
        "sla_fail_ticks": sla_fail_ticks,
        "techniques": sorted(techniques.values(), key=lambda t: t["first_tick"]),
        "traffic": [{"tick": t, **dict(c)} for t, c in sorted(per_tick.items())],
    }
