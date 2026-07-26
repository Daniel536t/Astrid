# Astrid — Your Machine's AI SRE

An autonomous AI agent that watches your machine's network via SigNoz, explains what it sees in plain English, and fixes problems with one click.

**Repo:** https://github.com/Daniel536t/Astrid · **Demo video:** _[link TBD — see Screenshots](#screenshots)_

## The Problem

Your machine talks to the internet constantly — and won't tell you who it's talking to. Background processes silently drain bandwidth and beam data to unknown destinations, and the only tools you get are Task Manager and `netstat`: walls of PIDs and IP addresses that mean nothing to a non-technical user. Astrid started from a real mystery: an `svchost.exe` process pushing megabytes to an unknown endpoint with no way to tell whether it was Windows Update or something worse.

## The Solution: An AI SRE That Lives on Your Machine

Astrid runs the same loop a site-reliability engineer runs — perception, reasoning, action, observation — but for a personal machine:

- **Perceive** — a lightweight agent captures per-process network traffic and ships it to SigNoz as OpenTelemetry metrics, attributed by process, remote domain, company, and category.
- **Reason** — when a SigNoz alert fires, the analyst pulls context straight from SigNoz and asks an LLM for a structured verdict: what is this process, who is receiving the data, and is it RED (suspicious), YELLOW, or GREEN?
- **Act** — the console shows a plain-English verdict card. One click on **Fix It** kills the process. Autonomous mode can remediate without asking.
- **Be observed** — the agent and analyst are themselves OTel-instrumented, so the watchdog's own reasoning loop shows up as traces and metrics in the same SigNoz. **The watchdog watches itself.**

## Architecture

```
┌──────────────┐   OTLP metrics    ┌─────────────┐   threshold alert   ┌───────────────┐
│ astrid-agent │ ────────────────▶ │   SigNoz    │ ──────────────────▶ │    analyst    │
│ (ss/psutil,  │  net.bytes_sent   │  v0.133 EE  │   (webhook channel) │  (FastAPI)    │
│  loopback    │  net.bytes_recv   │  ClickHouse │                     │               │
│  tcp_info)   │  net.new_domain_* │             │                     │               │
└──────────────┘                   └──────┬──────┘                     └───────┬───────┘
       ▲                                  │                                    │
       │ kill(pid) / iptables             │  context query                     │ NVIDIA NIM
       │                                  │  (ClickHouse SQL)                  ▼
┌──────┴───────┐                          │                            ┌───────────────┐
│  remediation │ ◀── Fix It / Block All ──┴─────────────────────────── │  LLM verdict  │
│  (actuator)  │      console UI :9000   (SigNoz ⇄ Astrid toggle,      │  (structured  │
└──────────────┘                           Demo Mode for judges)        │   JSON out)   │
                                                                        └───────────────┘
```

- **OpenTelemetry metrics** — `net.bytes_sent`, `net.bytes_recv`, `net.new_domain_seen`, labeled with `process_name`, `remote_domain`, `company`, `category`.
- **SigNoz alert webhooks** — `Astrid: Background drain detected` threshold rule → webhook channel → analyst `/alert`.
- **LLM via NVIDIA NIM** — Llama 3.1 70B Instruct, structured JSON verdicts (risk, explanation, action), grounded in the fetched evidence.
- **FastAPI console** — one page, two views: **Astrid** (plain-English mission control) and **SigNoz** (raw metrics, embedded). Verdict cards, world map of destinations, bandwidth charts, tracker blocking, `/chat`.

## For Judges

**The console is live and public — test the real system at <http://13.217.12.249:9000/>.** Every chart and verdict is real telemetry from that machine, and the fixes really execute. Nothing is stubbed.

Want the Windows storyline (`chrome.exe`, `svchost.exe`, `spotify.exe`)? Flip **DEMO MODE** in the header — the UI serves synthetic-but-realistic telemetry with fake verdicts, simulated bandwidth, and companies like Google/Netflix/Amazon. **Fix It** and **Block All** are fully simulated, so every button is safe to mash — the AI chat stays live either way. Toggle state persists in `localStorage`.

The header's **ASTRID ⇄ SIGNOZ** toggle switches between the AI console and the raw SigNoz backend it reads from — *"SigNoz shows raw metrics. Astrid explains them."* The SigNoz view embeds the **Bandwidth Vampires** dashboard (processes ranked by data sent: top 1h, flow 6h, process→destination 1h, total 24h). SigNoz keeps its own login — use the demo credentials shared with judges; without them you'll see SigNoz's sign-in page.

**Things to try live:**

- **ANALYZE NOW** (LIVE VERDICTS header) — runs the same verdict pipeline as real alerts against the current top talkers. Or hit the per-process **analyze** button in TOP PROCESSES · 24H to give any process (try `claude`) the full card treatment: what it is, how much data, kill-or-dismiss decision.
- **ASK ASTRID** — every answer carries a footer with latency, token count and model. Those same LLM calls are **traced into SigNoz** (service `astrid-analyst`, `llm.chat` / `llm.verdict` spans with `gen_ai.*` token attributes) — AI-agent observability applied to Astrid itself.
- The map and panels show a `web-surfer` process visiting YouTube/GitHub/Wikipedia — that's an honestly-labeled simulator generating **real** HTTPS traffic so a headless server has recognizable destinations. Ask the chat about it; it'll tell you exactly that.

## Setup

### 1. SigNoz (observability backend)

Installed via Foundry CLI (v0.2.16) → Docker Compose, SigNoz v0.133.0 EE (see [`deploy/README.md`](deploy/README.md)):

```bash
foundryctl install          # pulls the compose stack into ~/signoz-deploy
cd ~/signoz-deploy/pours/deployment && docker compose up -d
# first boot only: register an org so the OpAMP ingester activates
curl -X POST http://localhost:8080/api/v1/register -H 'Content-Type: application/json' \
  -d '{"email":"admin@astrid.local","password":"<pick-one>","orgName":"Astrid","name":"admin"}'
```

SigNoz UI lands on **:8080**; OTLP receivers on **:4317** (gRPC) / **:4318** (HTTP).

### 2. Capture agent (per-process network metrics)

```bash
python3 -m venv analyst/venv && analyst/venv/bin/pip install -r agent/requirements.txt  # psutil, opentelemetry, setproctitle
sudo analyst/venv/bin/python3 agent/agent_linux.py     # needs root for ss/tcp_info + nethogs-class capture
```

Runs as `astrid-agent.service` (systemd) on the demo box.

### 3. Analyst (LLM brain + console)

```bash
analyst/venv/bin/pip install fastapi uvicorn httpx openai psutil
cp analyst/.env.example analyst/.env    # NIM_API_KEY, SIGNOZ_API_KEY, CLICKHOUSE_HTTP
analyst/venv/bin/uvicorn analyst:app --host 0.0.0.0 --port 9000 --app-dir analyst
```

Console: **http://localhost:9000** · Runs as `astrid-analyst.service` on the demo box.

### 4. Wire the alert loop

In SigNoz: create a metrics alert on `net.bytes_sent` (threshold, 5-min window) → webhook channel → `http://<host>:9000/alert`. The next bandwidth spike produces a verdict card in the console.

### 5. (Optional) Hermetic demo traffic

```bash
python3 demo/sink.py &                  # discards POSTs on 127.0.0.1:9999
python3 demo/vampire.py --mbps 5 &      # drains bandwidth as "svc-updater" — watch Astrid catch it
```

## Demo

The full loop, proven end to end: a bandwidth vampire (`svc-updater`, a demo process pushing ~300 MB) was detected by the SigNoz alert, explained by the LLM (**RED**: "high data usage by an unknown process is suspicious"), shown in the console, and killed via the **Fix It** button. Raw evidence: [`DEMO-EVIDENCE.json`](DEMO-EVIDENCE.json).

## Screenshots

- [ ] **Hero panel** — "Where Your Data Goes" world map with live arcs to destinations (`docs/shots/hero-panel.png`) — TODO
- [ ] **Verdict card** — RED `svc-updater` card with plain-English explanation (`docs/shots/verdict-card.png`) — TODO
- [ ] **Fix It** — one-click remediation, before → FIXED ✓ (`docs/shots/fix-it.png`) — TODO
- [ ] **Block All** — tracker domains firewalled in one click (`docs/shots/block-all.png`) — TODO
- [ ] **SigNoz toggle** — raw-metrics view embedded in the console (`docs/shots/signoz-toggle.png`) — TODO
- [ ] **Demo Mode** — synthetic data banner for judges (`docs/shots/demo-mode.png`) — TODO

Earlier raw captures live in `journal/demo-assets/` (JSON evidence, dashboard/alert exports).

## Track 1: AI & Agent Observability

| Requirement | How Astrid delivers |
|---|---|
| **AI agent with E2E observability** | The agent and analyst are OTel-instrumented; the analyst's investigation loop (alert received → context query → LLM call → verdict) is traced and its metrics land in the same SigNoz it reads from. |
| **SRE Sidekick** | The analyst reads live SigNoz data (ClickHouse context queries) and answers questions in plain English via `/chat` — "who is python3 talking to?" gets an answer grounded in real telemetry, with an explicit "not enough information" fallback instead of speculation. |
| **Self-healing infrastructure** | The full loop is closed: metric spike → SigNoz alert → LLM diagnosis → one-click (or automatic) kill → the bandwidth metric flatlines, visible on the dashboard. |

## Tech Stack

Python · OpenTelemetry · SigNoz v0.133 EE (ClickHouse + Postgres) · FastAPI · NVIDIA NIM (Llama 3.1 70B Instruct) · systemd · psutil / `ss` tcp_info · vanilla JS/SVG console (no build step, no CDNs)

## Roadmap

- **Windows agent** — the original svchost use case (scaffolding in `agent/`)
- **Browser extension** — per-site tracker attribution, closing the gap between "process" and "tab"
- **Android agent** — via local VPN tunnel for per-app traffic capture
- **Multi-machine console** — one console watching every machine you own
