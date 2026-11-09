"""Live engagement API + WebSocket stream (optional ``api`` extra).

Start the server:

    uvicorn sentinel_arena.api.server:app --reload

Then open http://127.0.0.1:8000 for the live arena view. POST /engagements to
launch a run; the arena page streams its events over a WebSocket as the referee
ticks.

This is a thin, optional layer over the same ``run_engagement`` used by the CLI
— the engagement logic and every safety control live below it, not here.
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "The API requires the 'api' extra: pip install 'sentinel-arena[api]'"
    ) from e

import json as _json

from ..engagement import run_engagement
from ..scenarios.loader import list_scenarios

app = FastAPI(title="Sentinel Arena")
# The Next.js dev server (localhost:3000) and the built app talk to this API
# cross-origin, so allow it. Tighten the origins for a real deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
_STATIC = Path(__file__).parent / "static"

# engagement_id -> {"events": [...], "status": str, "result": dict|None, "dir": str}
_ENGAGEMENTS: dict[str, dict] = {}


def _launch(engagement_id: str, scenario: str, seed: int, blue: str) -> None:
    state = _ENGAGEMENTS[engagement_id]

    def on_event(ev) -> None:
        state["events"].append(ev.model_dump())

    try:
        art = run_engagement(scenario, seed=seed, blue_name=blue,
                            out_dir=f"var/engagements/{engagement_id}",
                            on_event=on_event)
        sb = art.result.scoreboard
        state["result"] = {
            "resilience": sb.resilience, "red": sb.red.total, "blue": sb.blue.total,
            "flag_captured": sb.red.flag_captured, "ended": art.result.ended_reason,
            "report": f"/engagements/{engagement_id}/report",
        }
        state["dir"] = str(art.out_dir)
    except Exception as e:  # pragma: no cover
        state["result"] = {"error": str(e)}
    finally:
        state["status"] = "done"


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_STATIC / "arena.html").read_text(encoding="utf-8")


@app.post("/engagements")
def start_engagement(scenario: str = "shop-01", seed: int = 42, blue: str = "scripted"):
    engagement_id = uuid.uuid4().hex[:12]
    _ENGAGEMENTS[engagement_id] = {"events": [], "status": "running",
                                   "result": None, "dir": ""}
    threading.Thread(target=_launch,
                     args=(engagement_id, scenario, seed, blue),
                     daemon=True).start()
    return {"id": engagement_id}


@app.get("/scenarios")
def scenarios():
    return {"scenarios": list_scenarios()}


@app.get("/engagements/{engagement_id}")
def engagement_status(engagement_id: str):
    state = _ENGAGEMENTS.get(engagement_id)
    if state is None:
        return JSONResponse({"error": "unknown engagement"}, status_code=404)
    return {"id": engagement_id, "status": state["status"],
            "events": len(state["events"]), "result": state["result"]}


@app.get("/engagements/{engagement_id}/result")
def engagement_result(engagement_id: str):
    """Full scoreboard + findings JSON for the native report page."""
    state = _ENGAGEMENTS.get(engagement_id)
    if not state or not state.get("dir"):
        return JSONResponse({"error": "not ready"}, status_code=404)
    result_file = Path(state["dir"]) / "result.json"
    if not result_file.exists():
        return JSONResponse({"error": "not ready"}, status_code=404)
    return _json.loads(result_file.read_text(encoding="utf-8"))


@app.get("/leaderboard")
def leaderboard(seeds: str = "42,7,101", scenario: str = "shop-01"):
    """Run a quick benchmark across registered agents and return the table data."""
    from ..leaderboard import run_benchmark

    seed_list = [int(x) for x in seeds.split(",") if x.strip()]
    stats = run_benchmark(seeds=seed_list, scenario=scenario)
    return {"scenario": scenario, "seeds": seed_list,
            "rows": [s.model_dump() for s in stats]}


@app.get("/engagements/{engagement_id}/report", response_class=HTMLResponse)
def report(engagement_id: str):
    state = _ENGAGEMENTS.get(engagement_id)
    if not state or not state.get("dir"):
        return HTMLResponse("<h1>Report not ready</h1>", status_code=404)
    return FileResponse(Path(state["dir"]) / "report.html")


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
            if state["status"] == "done" and sent >= len(state["events"]):
                await websocket.send_json({"type": "done", "result": state["result"]})
                break
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:  # pragma: no cover
        return
    await websocket.close()
