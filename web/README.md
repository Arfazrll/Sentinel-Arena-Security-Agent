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
| `/` | **Live arena.** Start an engagement; a React Flow network map lights up as the attacker reaches endpoints, a split-screen red/blue timeline streams over WebSocket, and the resilience score updates live. |
| `/leaderboard` | Runs the benchmark (`GET /leaderboard`) and tabulates red × blue agents across seeds. |
| `/report/[id]` | Native resilience report for one engagement — score, OWASP findings, mitigations — plus a link to the full HTML/PDF report. |

## Config

`NEXT_PUBLIC_API_BASE` (default `http://127.0.0.1:8000`) sets the backend URL.
The backend enables permissive CORS for local dev; tighten it for deployment.

## Build

```bash
npm run build     # verified: compiles and type-checks all routes
```
