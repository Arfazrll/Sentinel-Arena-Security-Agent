"""Live engagement API + WebSocket stream (optional ``api`` extra).

Start the server:

    uvicorn sentinel_arena.api.server:app --reload

The Next.js app in ``web/`` is the main client. Every endpoint is a thin layer
over the same ``run_engagement`` the CLI uses - the engagement logic and every
safety control live below it, not here.

Engagement history persists on disk under ``$ARENA_DATA_DIR/engagements``
(default ``var/engagements``) and is reloaded on startup. There is deliberately
no DELETE: each engagement carries a tamper-evident audit trail, and the API
does not offer a way to erase one.
"""

from __future__ import annotations

import json as _json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "The API requires the 'api' extra: pip install 'sentinel-arena[api]'"
    ) from e

from .. import __version__
from ..agents import registry
from ..authz.audit import AuditLog, ChainBroken
from ..engagement import run_engagement
from ..engine.killswitch import KillSwitch
from ..report.compliance import enrich
from ..report.exports import to_csv, to_navigator_layer, to_sarif
from ..scenarios.loader import list_scenarios, load_scenario

app = FastAPI(title="Sentinel Arena", version=__version__)
# The Next.js dev server (localhost:3000) talks to this API cross-origin.
# Tighten the origins for a real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
_STATIC = Path(__file__).parent / "static"
DATA_DIR = Path(os.environ.get("ARENA_DATA_DIR", "var"))
ENG_ROOT = DATA_DIR / "engagements"
BENCH_FILE = DATA_DIR / "bench" / "latest.json"
MAX_CONCURRENT = 4  # each engagement stands up its own range server
_STARTED = time.time()

_LOCK = threading.Lock()
# engagement_id -> state dict (see _new_state)
_ENGAGEMENTS: dict[str, dict] = {}
_BENCHMARKS: dict[str, dict] = {}
_CAMPAIGNS: dict[str, dict] = {}
CAMP_ROOT = DATA_DIR / "campaigns"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_state(**kw) -> dict:
    return {"events": [], "status": "running", "result": None, "dir": "",
            "kill": None, "error": None, "created_at": _now(), **kw}


def _read_json(path: Path):
    try:
        return _json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_history() -> None:
    """Rebuild the in-memory index from engagements already on disk."""
    if not ENG_ROOT.exists():
        return
    for d in ENG_ROOT.iterdir():
        res = _read_json(d / "result.json") if d.is_dir() else None
        if not res or d.name in _ENGAGEMENTS:
            continue
        meta = res.get("meta", {})
        _ENGAGEMENTS[d.name] = _new_state(
            status="done", dir=str(d), scenario=res.get("scenario"),
            seed=res.get("seed"), red=meta.get("red", "scripted"),
            blue=meta.get("blue", "scripted"),
            created_at=meta.get("started_at")
            or datetime.fromtimestamp(d.stat().st_mtime, timezone.utc).isoformat(),
            result=_result_brief(d.name, res),
        )


def _result_brief(engagement_id: str, res: dict) -> dict:
    sb = res["scoreboard"]
    return {
        "resilience": sb["resilience"], "red": _red_total(sb["red"]),
        "blue": _blue_total(sb["blue"]), "flag_captured": sb["red"]["flag_captured"],
        "ended": res.get("ended"), "report": f"/engagements/{engagement_id}/report",
    }


def _red_total(r: dict) -> int:
    from ..engine.scoring import RedScore
    return RedScore(**r).total


def _blue_total(b: dict) -> int:
    from ..engine.scoring import BlueScore
    return BlueScore(**b).total


def _summary(eid: str, st: dict) -> dict:
    out = {
        "id": eid, "status": st["status"], "scenario": st.get("scenario"),
        "seed": st.get("seed"), "red": st.get("red"), "blue": st.get("blue"),
        "created_at": st.get("created_at"), "result": st.get("result"),
        "error": st.get("error"),
    }
    res = _read_json(Path(st["dir"]) / "result.json") if st.get("dir") else None
    if res:
        meta, kpis = res.get("meta", {}), res.get("kpis", {})
        sev: dict[str, int] = {}
        for f in res.get("findings", []):
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        out.update({
            "scenario_name": meta.get("scenario_name"),
            "red_label": meta.get("red_label"), "blue_label": meta.get("blue_label"),
            "finished_at": meta.get("finished_at"), "ticks_run": res.get("ticks_run"),
            "max_ticks": res.get("max_ticks"), "duration_s": res.get("duration_s"),
            "findings": len(res.get("findings", [])), "severity": sev,
            "time_to_detect": kpis.get("time_to_detect"),
            "time_to_contain": kpis.get("time_to_contain"),
            "dwell_ticks": kpis.get("dwell_ticks"),
            "attacker_block_rate": kpis.get("attacker_block_rate"),
            "false_blocks": res["scoreboard"]["blue"].get("false_blocks", 0),
        })
    return out


def _get(eid: str) -> dict:
    st = _ENGAGEMENTS.get(eid)
    if st is None:
        raise HTTPException(404, "unknown engagement")
    return st


def _result_file(eid: str) -> dict:
    st = _get(eid)
    res = _read_json(Path(st["dir"]) / "result.json") if st.get("dir") else None
    if res is None:
        raise HTTPException(404, "not ready")
    # Runs recorded before compliance enrichment existed get it on read.
    res["findings"] = [f if "rule_id" in f else enrich(f)
                       for f in res.get("findings", [])]
    return res


def _launch(eid: str, scenario: str, seed: int, red: str, blue: str,
            tick_delay_s: float) -> None:
    state = _ENGAGEMENTS[eid]

    def on_event(ev) -> None:
        state["events"].append(ev.model_dump())

    try:
        art = run_engagement(scenario, seed=seed, red_name=red, blue_name=blue,
                             out_dir=ENG_ROOT / eid, on_event=on_event,
                             killswitch=state["kill"], tick_delay_s=tick_delay_s)
        state["dir"] = str(art.out_dir)
        res = _read_json(art.out_dir / "result.json")
        state["result"] = _result_brief(eid, res)
        state["status"] = "stopped" if state["kill"].tripped else "done"
    except Exception as e:  # pragma: no cover
        state["error"] = str(e)
        state["result"] = {"error": str(e)}
        state["status"] = "error"


_load_history()


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "arena.html").read_text(encoding="utf-8")


@app.get("/healthz")
def healthz():
    running = sum(1 for s in _ENGAGEMENTS.values() if s["status"] == "running")
    return {"status": "ok", "version": __version__,
            "uptime_s": round(time.time() - _STARTED, 1),
            "engagements": len(_ENGAGEMENTS), "running": running,
            "max_concurrent": MAX_CONCURRENT}


@app.get("/agents")
def agents():
    return {"agents": registry.all_agents()}


@app.get("/scenarios")
def scenarios():
    items = []
    for sid in list_scenarios():
        sc = load_scenario(sid)
        items.append({
            "id": sc.id, "name": sc.name, "description": sc.description.strip(),
            "max_ticks": sc.max_ticks, "randomize": sc.randomize,
            "health_path": sc.health.path,
            "weaknesses": [w.model_dump() for w in sc.weaknesses],
        })
    return {"scenarios": list_scenarios(), "items": items}


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
@app.post("/engagements")
def start_engagement(
    scenario: str = "shop-01",
    seed: int = Query(42, ge=0, le=2**31 - 1),
    red: str = "scripted",
    blue: str = "scripted",
    pace_ms: int = Query(0, ge=0, le=3000,
                         description="Delay between ticks so a viewer can follow."),
):
    if scenario not in list_scenarios():
        raise HTTPException(400, f"unknown scenario {scenario!r}")
    for team, name in (("red", red), ("blue", blue)):
        try:
            spec = registry.get(team, name)
        except KeyError as e:
            raise HTTPException(400, str(e))
        if not spec.available():
            raise HTTPException(400, f"{team} agent {name!r} is not available "
                                     "(missing ANTHROPIC_API_KEY?)")
    with _LOCK:
        running = sum(1 for s in _ENGAGEMENTS.values() if s["status"] == "running")
        if running >= MAX_CONCURRENT:
            raise HTTPException(429, f"{running} engagements already running; "
                                     "wait for one to finish")
        eid = uuid.uuid4().hex[:12]
        _ENGAGEMENTS[eid] = _new_state(scenario=scenario, seed=seed, red=red,
                                       blue=blue, kill=KillSwitch())
    threading.Thread(target=_launch,
                     args=(eid, scenario, seed, red, blue, pace_ms / 1000.0),
                     daemon=True).start()
    return {"id": eid}


@app.get("/engagements")
def list_engagements(limit: int = Query(200, ge=1, le=1000)):
    rows = [_summary(eid, st) for eid, st in _ENGAGEMENTS.items()]
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return {"engagements": rows[:limit], "total": len(rows)}


@app.get("/engagements/{engagement_id}")
def engagement_status(engagement_id: str):
    st = _get(engagement_id)
    return {**_summary(engagement_id, st), "events": len(st["events"])}


@app.post("/engagements/{engagement_id}/stop")
def stop_engagement(engagement_id: str, reason: str = "operator kill switch"):
    st = _get(engagement_id)
    if st["status"] != "running" or st.get("kill") is None:
        return {"id": engagement_id, "status": st["status"], "stopped": False}
    st["kill"].trip(reason[:120])
    return {"id": engagement_id, "status": "stopping", "stopped": True}


@app.get("/engagements/{engagement_id}/result")
def engagement_result(engagement_id: str):
    """Full scoreboard, findings, KPIs and per-tick timeline."""
    return _result_file(engagement_id)


@app.get("/engagements/{engagement_id}/events")
def engagement_events(engagement_id: str):
    st = _get(engagement_id)
    if st["events"]:
        return {"events": st["events"]}
    path = Path(st["dir"]) / "events.jsonl" if st.get("dir") else None
    if not path or not path.exists():
        raise HTTPException(404, "no events")
    with path.open(encoding="utf-8") as fh:
        events = [_json.loads(line) for line in fh if line.strip()]
    return {"events": events}


@app.get("/engagements/{engagement_id}/audit")
def engagement_audit(engagement_id: str, limit: int = Query(500, ge=1, le=5000)):
    st = _get(engagement_id)
    path = Path(st["dir"]) / "audit.jsonl" if st.get("dir") else None
    if not path or not path.exists():
        raise HTTPException(404, "no audit trail")
    log = AuditLog(path)
    entries = [_json.loads(e.to_json()) for e in log]
    try:
        verified, error = log.verify_chain(), None
    except ChainBroken as e:
        verified, error = False, str(e)
    counts: dict[str, int] = {}
    for e in entries:
        k = f"{e['action']}:{e['outcome']}"
        counts[k] = counts.get(k, 0) + 1
    return {"verified": verified, "error": error, "total": len(entries),
            "counts": counts, "tip": entries[-1]["entry_hash"] if entries else None,
            "entries": entries[:limit]}


@app.get("/engagements/{engagement_id}/export/{fmt}")
def export(engagement_id: str, fmt: str):
    res = _result_file(engagement_id)
    name = f"sentinel-arena-{engagement_id}"
    disp = lambda ext: {"Content-Disposition": f'attachment; filename="{name}.{ext}"'}
    if fmt == "sarif":
        return JSONResponse(to_sarif(res), headers=disp("sarif"))
    if fmt == "navigator":
        events = engagement_events(engagement_id)["events"]
        return JSONResponse(to_navigator_layer(res, events),
                            headers=disp("layer.json"))
    if fmt == "csv":
        return PlainTextResponse(to_csv(res), media_type="text/csv",
                                 headers=disp("csv"))
    if fmt == "json":
        return JSONResponse(res, headers=disp("json"))
    if fmt == "md":
        md = Path(_get(engagement_id)["dir"]) / "report.md"
        if not md.exists():
            raise HTTPException(404, "no markdown report")
        return PlainTextResponse(md.read_text(encoding="utf-8"),
                                 media_type="text/markdown", headers=disp("md"))
    raise HTTPException(400, "format must be one of sarif, navigator, csv, json, md")


@app.get("/engagements/{engagement_id}/report", response_class=HTMLResponse)
def report(engagement_id: str):
    st = _ENGAGEMENTS.get(engagement_id)
    if not st or not st.get("dir") or not (Path(st["dir"]) / "report.html").exists():
        return HTMLResponse("<h1>Report not ready</h1>", status_code=404)
    return FileResponse(Path(st["dir"]) / "report.html")


@app.get("/findings")
def findings():
    """Findings aggregated across every completed engagement, de-duplicated by
    rule - the input for a remediation backlog."""
    agg: dict[str, dict] = {}
    for eid, st in _ENGAGEMENTS.items():
        res = _read_json(Path(st["dir"]) / "result.json") if st.get("dir") else None
        if not res:
            continue
        when = res.get("meta", {}).get("finished_at") or st.get("created_at")
        for f in res.get("findings", []):
            f = f if "rule_id" in f else enrich(f)
            rid = f["rule_id"]
            a = agg.setdefault(rid, {**f, "occurrences": 0, "engagements": [],
                                     "first_seen": when, "last_seen": when})
            a["occurrences"] += 1
            a["engagements"].append(eid)
            a["first_seen"] = min(a["first_seen"] or when, when or "")
            a["last_seen"] = max(a["last_seen"] or when, when or "")
    rows = sorted(agg.values(), key=lambda f: (-f.get("risk_score", 0), f["title"]))
    return {"findings": rows, "total": len(rows)}


# ---------------------------------------------------------------------------
# Benchmarks (leaderboard)
# ---------------------------------------------------------------------------
def _run_bench(job_id: str, seeds: list[int], reds, blues, scenario: str) -> None:
    from ..leaderboard import run_benchmark

    job = _BENCHMARKS[job_id]

    def progress(done, total, label):
        job.update(done=done, total=total, current=label)

    try:
        stats = run_benchmark(seeds=seeds, reds=reds, blues=blues,
                              scenario=scenario, on_progress=progress)
        job["rows"] = [s.model_dump() for s in stats]
        job["status"] = "done"
        job["finished_at"] = _now()
        BENCH_FILE.parent.mkdir(parents=True, exist_ok=True)
        BENCH_FILE.write_text(_json.dumps(job, indent=2), encoding="utf-8")
    except Exception as e:  # pragma: no cover
        job["status"] = "error"
        job["error"] = str(e)


def _names(csv_: str, team: str) -> list[str] | None:
    names = [n.strip() for n in csv_.split(",") if n.strip()]
    for n in names:
        try:
            registry.get(team, n)
        except KeyError as e:
            raise HTTPException(400, str(e))
    return names or None


@app.post("/benchmarks")
def start_benchmark(seeds: str = "42,7,101", reds: str = "", blues: str = "",
                    scenario: str = "shop-01"):
    try:
        seed_list = [int(x) for x in seeds.split(",") if x.strip()]
    except ValueError:
        raise HTTPException(400, "seeds must be comma-separated integers")
    if not 1 <= len(seed_list) <= 10:
        raise HTTPException(400, "use between 1 and 10 seeds")
    if scenario not in list_scenarios():
        raise HTTPException(400, f"unknown scenario {scenario!r}")
    red_list, blue_list = _names(reds, "red"), _names(blues, "blue")
    if any(j["status"] == "running" for j in _BENCHMARKS.values()):
        raise HTTPException(429, "a benchmark is already running")
    job_id = uuid.uuid4().hex[:10]
    total = (len(red_list or registry.benchmark_names("red"))
             * len(blue_list or registry.benchmark_names("blue")) * len(seed_list))
    _BENCHMARKS[job_id] = {"id": job_id, "status": "running", "scenario": scenario,
                           "seeds": seed_list, "done": 0, "total": total,
                           "current": "", "rows": [], "started_at": _now()}
    threading.Thread(target=_run_bench,
                     args=(job_id, seed_list, red_list, blue_list, scenario),
                     daemon=True).start()
    return {"id": job_id, "total": total}


@app.get("/benchmarks/latest")
def latest_benchmark():
    done = [j for j in _BENCHMARKS.values() if j["status"] == "done"]
    if done:
        return max(done, key=lambda j: j.get("finished_at", ""))
    saved = _read_json(BENCH_FILE)
    if saved:
        return saved
    raise HTTPException(404, "no benchmark has been run yet")


@app.get("/benchmarks/{job_id}")
def benchmark_status(job_id: str):
    job = _BENCHMARKS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown benchmark")
    return job


# --- campaigns: assess a target across a matrix -> one verdict -------------
def _load_campaign_history() -> None:
    if not CAMP_ROOT.exists():
        return
    for child in sorted(CAMP_ROOT.iterdir()):
        data = _read_json(child / "campaign.json")
        if data and data.get("id") not in _CAMPAIGNS:
            _CAMPAIGNS[data["id"]] = {
                "id": data["id"], "status": "done", "done": data["runs"],
                "total": data["runs"], "current": "", "result": data,
                "finished_at": data.get("created_at", "")}


def _run_campaign_job(job_id: str, plan) -> None:
    from ..campaign import run_campaign, save_campaign

    job = _CAMPAIGNS[job_id]

    def progress(done, total, label):
        job.update(done=done, total=total, current=label)

    try:
        res = run_campaign(plan, on_progress=progress, campaign_id=job_id)
        save_campaign(res, CAMP_ROOT / job_id)
        job["result"] = res.model_dump()
        job["status"] = "done"
        job["finished_at"] = _now()
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)


@app.post("/campaigns")
def start_campaign(target: str = "127.0.0.1", depth: str = "standard",
                   scenarios_csv: str = "", label: str = "",
                   i_own_this: bool = False):
    from ..campaign import CampaignPlan

    if depth not in ("quick", "standard", "deep"):
        raise HTTPException(400, "depth must be quick, standard or deep")
    sel = [s.strip() for s in scenarios_csv.split(",") if s.strip()]
    for s in sel:
        if s not in list_scenarios():
            raise HTTPException(400, f"unknown scenario {s!r}")
    if any(j["status"] == "running" for j in _CAMPAIGNS.values()):
        raise HTTPException(429, "a campaign is already running")
    plan = CampaignPlan(target=target, depth=depth, scenarios=sel, label=label,
                        ownership_proven=i_own_this)
    try:
        total = plan.total_runs()
    except ValueError as e:
        raise HTTPException(400, str(e))
    job_id = "camp-" + uuid.uuid4().hex[:10]
    _CAMPAIGNS[job_id] = {"id": job_id, "status": "running", "target": target,
                          "depth": depth, "label": label, "done": 0,
                          "total": total, "current": "", "result": None,
                          "started_at": _now()}
    threading.Thread(target=_run_campaign_job, args=(job_id, plan),
                     daemon=True).start()
    return {"id": job_id, "total": total}


@app.get("/campaigns")
def list_campaigns(limit: int = Query(100, ge=1, le=500)):
    _load_campaign_history()
    jobs = sorted(_CAMPAIGNS.values(),
                  key=lambda j: j.get("finished_at") or j.get("started_at") or "",
                  reverse=True)
    return [{k: j.get(k) for k in ("id", "status", "target", "depth", "label",
                                   "done", "total", "started_at", "finished_at")}
            | ({"grade": j["result"]["posture_grade"],
                "worst_resilience": j["result"]["worst_resilience"],
                "findings": len(j["result"]["vulnerabilities"])}
               if j.get("result") else {})
            for j in jobs[:limit]]


@app.get("/campaigns/{job_id}")
def campaign_status(job_id: str):
    _load_campaign_history()
    job = _CAMPAIGNS.get(job_id)
    if job is None:
        raise HTTPException(404, "unknown campaign")
    return job


@app.get("/campaigns/{job_id}/report", response_class=PlainTextResponse)
def campaign_report(job_id: str):
    job = _CAMPAIGNS.get(job_id)
    if job is None or not job.get("result"):
        raise HTTPException(404, "no finished campaign with that id")
    from ..campaign import CampaignResult, to_markdown
    return to_markdown(CampaignResult.model_validate(job["result"]))


@app.get("/leaderboard")
def leaderboard(seeds: str = "42,7,101", scenario: str = "shop-01"):
    """Synchronous benchmark (kept for scripts). The web app uses /benchmarks."""
    from ..leaderboard import run_benchmark

    seed_list = [int(x) for x in seeds.split(",") if x.strip()]
    stats = run_benchmark(seeds=seed_list, scenario=scenario)
    return {"scenario": scenario, "seeds": seed_list,
            "rows": [s.model_dump() for s in stats]}


# ---------------------------------------------------------------------------
# Live stream
# ---------------------------------------------------------------------------
@app.websocket("/ws/{engagement_id}")
async def ws(websocket: WebSocket, engagement_id: str):
    import asyncio

    await websocket.accept()
    state = _ENGAGEMENTS.get(engagement_id)
    if state is None:
        await websocket.send_json({"type": "error", "message": "unknown engagement"})
        await websocket.close()
        return
    sent = 0
    try:
        while True:
            events = state["events"]
            while sent < len(events):
                await websocket.send_json({"type": "event", "event": events[sent]})
                sent += 1
            if state["status"] != "running" and sent >= len(state["events"]):
                await websocket.send_json({"type": "done", "status": state["status"],
                                           "result": state["result"]})
                break
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:  # pragma: no cover
        return
    await websocket.close()
