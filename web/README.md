# Sentinel Arena — web (Next.js)

The frontend: a live arena view, a leaderboard, and a native resilience report
page. Next.js (App Router) + React + React Flow, talking to the FastAPI backend
over HTTP + WebSocket.

## Run

```bash
# 1. Start the backend API (from the repo root)
uv pip install -e ".[api]"
uvicorn sentinel_arena.api.server:app          # http://127.0.0.1:8000

# 2. Start the frontend
cd web
cp .env.local.example .env.local               # point at the API if not :8000
npm install
npm run dev                                     # http://localhost:3000
```

## Pages

| Route | What it shows |
| --- | --- |
| `/` | Overview: posture, KPI tiles, resilience trend, defenders, OWASP breakdown, recent runs. |
| `/arena` | Launch an engagement, then watch it live: agent panels, attack-surface graph, score/resilience/traffic charts, ATT&CK coverage, event log, emergency stop. |
| `/engagements` | History with search, outcome filter, sorting, CSV export, pick two to compare. |
| `/engagements/[id]` | Replay, findings, metrics, audit trail and export tabs for one run. |
| `/compare?a=&b=` | Two runs side by side: metric deltas, timelines, findings diff. |
| `/leaderboard` | Benchmarks: background job, resilience heatmap, ranked matchups, per-seed table. |
| `/remediation` | Cross-run findings backlog with status tracking (stored in the browser). |
| `/scenarios`, `/agents`, `/governance` | Catalogs and the trust & safety overview. |
| `/report/[id]` | Redirects to the Findings tab (old links keep working). |

## Design notes

- `lib/derive.ts` turns an event stream (cut at any tick) into everything the
  arena draws, so the live view and replay can't disagree.
- Charts are small hand-written SVG components (`components/charts.tsx`) with
  hover tooltips, legends and a table view on each card. Team colors (red,
  blue, aqua for real users) were checked with a colorblind-safety validator;
  legends and tables back up the color encoding.
- Theme tokens live in `app/globals.css`; dark and light are both designed,
  and the default follows the OS until the user picks one.

## Config

`NEXT_PUBLIC_API_BASE` (default `http://127.0.0.1:8000`) sets the backend URL.
The backend enables permissive CORS for local dev; tighten it for deployment.

## Build

```bash
npm run build     # verified: compiles and type-checks all routes
```
