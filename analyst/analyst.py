"""
Astrid AI Analyst — runs on EC2 alongside SigNoz.
Receives SigNoz alert webhooks -> pulls context -> LLM explains ->
queues notification+action for the Windows actuator to poll.
Phase 3: also serves the browser console (GET /) and executes Linux
remediation (POST /execute) directly on this host.
Console v2: adds /api/stats (live visualizations), /api/explain (plain-English
domain explainer), /api/geo (offline IP geolocation), /api/block-domain
(iptables blocking for ads/tracking) — all additive; every original endpoint
(/alert /pending /ack /chat /report /execute /) is unchanged in behavior.
"""

import os
import re
import time
import json
import uuid
import signal
import socket
import ipaddress
import threading
import subprocess
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

import httpx
import psutil
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from openai import OpenAI

# ────────────────────────── CONFIG ──────────────────────────
SIGNOZ_API_KEY = os.getenv("SIGNOZ_API_KEY", "")
NIM_API_KEY = os.getenv("NIM_API_KEY", "")
NIM_BASE = os.getenv("NIM_BASE", "https://integrate.api.nvidia.com/v1")
NIM_MODEL = os.getenv("NIM_MODEL", "meta/llama-3.1-70b-instruct")
ALLOWED_ACTIONS = ["block_domain", "disable_delivery_optimization", "set_metered", "kill_process", "ignore"]

# ClickHouse direct connection (bypasses SigNoz authz limitations on service accounts)
CLICKHOUSE_HTTP = os.getenv("CLICKHOUSE_HTTP", "http://172.18.0.6:8123")

llm = OpenAI(api_key=NIM_API_KEY, base_url=NIM_BASE)
app = FastAPI(title="Astrid Analyst")
pending = deque()
history = []
lock = threading.Lock()

# ────────────────────────── CLICKHOUSE CONTEXT ──────────────────────────
def ch_query(sql: str, timeout: float = 15) -> list | dict:
    """Run a ClickHouse SQL query and return parsed result (list of row dicts).

    JSONEachRow returns newline-delimited objects, so parse per line — a bare
    r.json() throws "Extra data" on any multi-row result (pre-existing bug:
    fetch_context silently received the error dict instead of metrics).
    """
    try:
        r = httpx.post(CLICKHOUSE_HTTP, data=sql, params={"default_format": "JSONEachRow"}, timeout=timeout)
        r.raise_for_status()
        body = r.text.strip()
        if not body:
            return []
        return [json.loads(line) for line in body.splitlines() if line.strip()]
    except httpx.HTTPStatusError as e:
        return {"error": f"clickhouse HTTP {e.response.status_code}: {e.response.text[:500]}"}
    except (json.JSONDecodeError, httpx.RequestError) as e:
        return {"error": f"clickhouse query failed: {e}"}

def fetch_context(process_name: str | None = None, minutes: int = 60) -> dict:
    """Pull recent traffic metrics from ClickHouse directly (v4 schema).

    TODO(#1): If Windows agent pushes net.bytes_sent etc. later, verify
    attribute key names match.  Use SigNoz DevTools method as alternative:
    build the query in SigNoz UI Metrics explorer → browser DevTools →
    Network tab → copy the JSON payload the UI sends to /api/v4/query_range
    — mirror that in a future fetch_context() that uses the API route.
    """
    try:
        cutoff = int((time.time() - minutes * 60) * 1000)  # unix_milli
        sql = f"""
            SELECT
                sv.metric_name,
                sv.value,
                sv.unix_milli,
                tv.attrs,
                tv.resource_attrs,
                tv.scope_attrs,
                tv.labels
            FROM signoz_metrics.samples_v4 sv
            JOIN signoz_metrics.time_series_v4 tv
                ON sv.fingerprint = tv.fingerprint
            WHERE sv.metric_name IN ('net.bytes_sent','net.bytes_recv','net.new_domain_seen')
              AND sv.unix_milli > {cutoff}
            ORDER BY sv.unix_milli DESC
            LIMIT 200
        """
        # 30s headroom: after a bandwidth flood, samples_v4 scans can take
        # ~20-25s (JOIN over hundreds of thousands of rows) — exceeds the 15s
        # default and chat then sees an error dict instead of evidence.
        rows = ch_query(sql, timeout=30)
        return {"metrics": rows, "count": len(rows), "source": "clickhouse_direct"}
    except Exception as e:
        return {"error": f"clickhouse query failed: {e}", "source": "clickhouse_direct"}

# ────────────────────────── DOMAIN CLASSIFICATION (mirrors agent_linux.py) ──────────────────────────
DOMAIN_CATEGORIES = {
    "ads": ["doubleclick.net", "googlesyndication.com", "adservice.google.com",
            "amazon-adsystem.com", "ads.yahoo.com", "advertising.com"],
    "tracking": ["google-analytics.com", "googletagmanager.com", "segment.io",
                 "segment.com", "mixpanel.com", "hotjar.com", "fullstory.com",
                 "telemetry.mozilla.org", "app-measurement.com"],
    "cdn": ["cloudfront.net", "akamaized.net", "akamai.net", "fastly.net",
            "cloudflare.com", "cdn77.org", "edgecastcdn.net", "jsdelivr.net"],
    "os-updates": ["windowsupdate.com", "update.microsoft.com", "archive.ubuntu.com",
                   "security.ubuntu.com", "ports.ubuntu.com", "apt.ubuntu.com",
                   "download.opensuse.org", "dl.fedoraproject.org"],
    "streaming": ["netflix.com", "nflxvideo.net", "youtube.com", "googlevideo.com",
                  "spotify.com", "scdn.co", "twitch.tv", "hulu.com"],
    "local": ["localhost", "lan"],
}
DOMAIN_COMPANIES = {
    "google": "Google", "googlevideo": "Google", "gstatic": "Google",
    "doubleclick": "Google", "googlesyndication": "Google", "googletagmanager": "Google",
    "google-analytics": "Google", "app-measurement": "Google",
    "microsoft": "Microsoft", "windowsupdate": "Microsoft", "azure": "Microsoft",
    "ubuntu": "Canonical", "amazon": "Amazon", "aws": "Amazon", "cloudfront": "Amazon",
    "netflix": "Netflix", "nflxvideo": "Netflix", "spotify": "Spotify",
    "facebook": "Meta", "fbcdn": "Meta", "cloudflare": "Cloudflare",
    "akamai": "Akamai", "mozilla": "Mozilla", "apple": "Apple",
    "yahoo": "Yahoo", "advertising": "Yahoo", "mixpanel": "Mixpanel",
    "hotjar": "Hotjar", "segment": "Segment", "fullstory": "FullStory",
    "anthropic": "Anthropic", "nvidia": "NVIDIA", "linode": "Akamai (Linode)",
    "localhost": "this machine", "lan": "local network",
}

def classify_domain(domain: str) -> tuple[str, str]:
    """Return (category, company) for a domain — same logic as the capture agent."""
    d = domain.lower().rstrip(".")
    for cat, suffixes in DOMAIN_CATEGORIES.items():
        if any(d == s or d.endswith("." + s) for s in suffixes):
            company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
            return cat, company
    company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
    return "unknown", company

# ────────────────────────── LLM ANALYSIS ──────────────────────────
SYSTEM_PROMPT = """You are Astrid, a network security analyst explaining network
activity to a NON-TECHNICAL computer user. You receive an alert from a monitoring
system plus recent traffic evidence.

Respond with ONLY valid JSON, no markdown, matching exactly this schema:
{
  "explanation": "2-4 plain-English sentences. What is this process? Why is it using
                  data? Name the company receiving the data if known. No jargon.",
  "risk": "GREEN" | "YELLOW" | "RED",
  "risk_reason": "one sentence",
  "action": one of ["block_domain","disable_delivery_optimization","set_metered","kill_process","ignore"],
  "action_params": {"domain": "...", "pid": 0}
}

Risk guide: GREEN = normal/expected. YELLOW = wasteful but not malicious
(Windows Delivery Optimization uploading to strangers, heavy telemetry,
background sync). RED = suspicious (unknown process, system-process name with
unusual traffic, never-seen destinations receiving large uploads, odd hours).
Prefer the least destructive action that solves the problem. kill_process is a last resort.

This host runs LINUX. Actions that work here: kill_process (stop the process),
block_domain (firewall a PUBLIC remote domain only), ignore. The Windows actions
(disable_delivery_optimization, set_metered) are NOT available — never choose them.
An unknown, non-OS process draining bandwidth at MB/s rates is RED and should be
killed, even if its destination looks local."""

def analyze(alert: dict, context: dict) -> dict:
    user_msg = (f"ALERT from SigNoz:\n{json.dumps(alert, indent=2)[:3000]}\n\n"
                f"RECENT TRAFFIC EVIDENCE (last hour):\n{json.dumps(context, indent=2)[:6000]}")
    try:
        resp = llm.chat.completions.create(
            model=NIM_MODEL,
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": user_msg}],
            temperature=0.2,
            max_tokens=600,
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1].removeprefix("json").strip()
        result = json.loads(raw)
        if result.get("action") not in ALLOWED_ACTIONS:
            result["action"] = "ignore"
        return result
    except Exception as e:
        return {"explanation": f"Analysis failed ({e}). Raw alert attached.",
                "risk": "YELLOW", "risk_reason": "analyst error, manual review",
                "action": "ignore", "action_params": {}}

# ────────────────────────── ENDPOINTS ──────────────────────────
@app.post("/alert")
async def receive_alert(request: Request):
    """SigNoz webhook lands here."""
    body = await request.json()
    for a in body.get("alerts", [body]):
        labels = a.get("labels", {})
        process = labels.get("process_name")
        context = fetch_context(process)
        verdict = analyze(a, context)
        item = {
            "id": str(uuid.uuid4()),
            "ts": time.time(),
            "alert_name": labels.get("alertname", "unknown"),
            "process_name": process,
            **verdict,
        }
        with lock:
            pending.append(item)
            history.append(item)
        print(f"[analyst] {item['risk']} | {item['alert_name']} | {item['explanation'][:80]}")
    return {"status": "queued"}

@app.get("/pending")
def get_pending():
    """Windows actuator polls this every 3s. Returns and clears the queue."""
    with lock:
        items = list(pending)
        pending.clear()
    return {"items": items}

@app.post("/ack")
async def ack(request: Request):
    body = await request.json()
    print(f"[ack] {body.get('id')} -> {body.get('outcome')}")
    with lock:
        for h in history:
            if h["id"] == body.get("id"):
                h["outcome"] = body.get("outcome")
    return {"ok": True}

@app.post("/chat")
async def chat(request: Request):
    q = (await request.json()).get("question", "")
    context = fetch_context(None, minutes=180)
    try:
        resp = llm.chat.completions.create(
            model=NIM_MODEL,
            messages=[{"role": "system", "content":
                       "You are Astrid. Answer the user's question about their PC's "
                       "network activity using the SigNoz evidence provided. Plain English, concise. "
                       "Only explain what the evidence shows. If evidence is incomplete or "
                       "unrelated, say 'I don't have enough information to answer that.' "
                       "Do not speculate or blame unrelated errors."},
                      {"role": "user", "content": f"Question: {q}\n\nEvidence:\n{json.dumps(context)[:8000]}"}],
            temperature=0.3, max_tokens=500, timeout=120,
        )
        return {"answer": resp.choices[0].message.content}
    except Exception as e:
        return {"answer": f"My brain (the LLM) is unreachable or too slow right now "
                          f"({type(e).__name__}). Try again in a moment — meanwhile the "
                          f"panels above still show your live traffic."}

@app.get("/report")
def report(demo: int = 0):
    if demo:
        return _demo_report()
    return {"analyzed": len(history), "items": history[-20:]}

# ────────────────────────── REMEDIATION (Phase 3, Linux) ──────────────────────────
PROTECTED_PROCS = {"systemd", "sshd", "sshd-session", "dockerd", "containerd",
                   "init", "systemd-resolved", "systemd-networkd"}
MIN_KILL_PID = 1000  # never touch low-pid system processes, demo targets only


def _kill_by_name(process_name: str) -> dict:
    """SIGTERM then SIGKILL every process whose name matches, with guards."""
    killed, errors = [], []
    self_pid = os.getpid()
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.info["name"] != process_name:
                continue
            if p.pid < MIN_KILL_PID:
                errors.append(f"refused pid {p.pid} (< {MIN_KILL_PID})")
                continue
            if p.pid == self_pid:
                errors.append("refused to kill self")
                continue
            cmdline = " ".join(p.info.get("cmdline") or [])
            if "analyst.py" in cmdline or "agent_linux.py" in cmdline:
                errors.append(f"refused pid {p.pid} (astrid infrastructure)")
                continue
            os.kill(p.pid, signal.SIGTERM)
            killed.append(p.pid)
        except (psutil.Error, ProcessLookupError, PermissionError) as e:
            errors.append(f"pid {p.pid}: {e}")
    if killed:
        time.sleep(1.5)
        for pid in killed:
            if psutil.pid_exists(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
    return {"killed": killed, "errors": errors}


@app.post("/execute")
async def execute(request: Request):
    """Browser console 'Fix It' button. Runs the Linux remediation for an item."""
    body = await request.json()
    if body.get("demo"):
        # Demo Mode: simulate the remediation, record it for ?demo=1 /report,
        # and never touch real processes, firewall rules, or verdict history.
        did = str(body.get("id", ""))
        outcome = _demo_execute_outcome(str(body.get("action", "")),
                                        str(body.get("process_name", "")),
                                        str((body.get("action_params") or {}).get("domain", "")))
        _DEMO_FIXES[did] = outcome
        print(f"[execute:demo] {did} :: {outcome}")
        return {"ok": True, "outcome": outcome, "id": did, "demo": True}
    item_id = body.get("id")
    with lock:
        item = next((h for h in history if h["id"] == item_id), None)
    if not item:
        return {"ok": False, "error": "unknown id"}
    action = item.get("action", "ignore")
    proc = item.get("process_name") or ""
    ok, outcome = True, ""

    if action == "kill_process":
        if proc in PROTECTED_PROCS:
            ok, outcome = False, f"refused: '{proc}' is a protected system process"
        else:
            res = _kill_by_name(proc)
            if res["killed"]:
                outcome = f"killed '{proc}' (pids {res['killed']})"
                if res["errors"]:
                    outcome += f"; warnings: {'; '.join(res['errors'])}"
            else:
                ok = False
                outcome = (f"no live process named '{proc}' found"
                           + (f"; {'; '.join(res['errors'])}" if res["errors"] else ""))
    elif action == "block_domain":
        domain = (item.get("action_params") or {}).get("domain", "")
        if not domain or domain in ("localhost", "lan", "unknown"):
            ok, outcome = False, f"refused: won't firewall local/unknown target '{domain}'"
        else:
            try:
                ip = socket.gethostbyname(domain)
                r = subprocess.run(["sudo", "-n", "iptables", "-A", "OUTPUT",
                                    "-d", ip, "-j", "DROP"],
                                   capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    outcome = f"blocked {domain} ({ip}) via iptables OUTPUT DROP"
                else:
                    ok, outcome = False, f"iptables failed: {r.stderr.strip()[:200]}"
            except Exception as e:
                ok, outcome = False, f"block failed: {e}"
    else:  # ignore / unsupported actions
        outcome = f"dismissed (action '{action}' needs no Linux remediation)"

    with lock:
        item["outcome"] = outcome
        item["fix_status"] = "fixed" if ok else "failed"
    print(f"[execute] {item_id} action={action} ok={ok} :: {outcome}")
    return {"ok": ok, "outcome": outcome, "id": item_id}

# ════════════════════════ CONSOLE V2 API (additive) ════════════════════════
# ────────────────────────── /api/stats ──────────────────────────
_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="astrid-dns")

def _resolve(name: str, timeout: float = 1.5) -> str | None:
    """DNS with a hard timeout so a slow resolver never stalls /api/stats."""
    try:
        return _DNS_POOL.submit(socket.gethostbyname, name).result(timeout=timeout)
    except Exception:
        return None

def _ptr(ip: str, timeout: float = 1.5) -> str | None:
    try:
        return _DNS_POOL.submit(lambda: socket.gethostbyaddr(ip)[0]).result(timeout=timeout)
    except Exception:
        return None

_STATS_CACHE: dict = {"ts": 0.0, "data": None}
_STATS_TTL = 2.0  # UI polls every 3s; serve fresh-ish without hammering ClickHouse

def _ch_rows(sql: str) -> list:
    rows = ch_query(sql)
    return rows if isinstance(rows, list) else []

def _stats_bandwidth(minutes: int = 30) -> list:
    """Per-minute byte deltas for both counters — cumulative-counter safe:
    (max-min) per fingerprint per minute bucket, summed across fingerprints."""
    cutoff = int((time.time() - minutes * 60) * 1000)
    rows = _ch_rows(f"""
        SELECT toUnixTimestamp(bucket) AS ts, m, sum(d) AS bytes
        FROM (
          SELECT fingerprint, metric_name AS m,
                 toStartOfMinute(fromUnixTimestamp64Milli(unix_milli)) AS bucket,
                 max(value) - min(value) AS d
          FROM signoz_metrics.samples_v4
          WHERE metric_name IN ('net.bytes_sent','net.bytes_recv')
            AND unix_milli > {cutoff}
          GROUP BY fingerprint, m, bucket
        )
        GROUP BY ts, m ORDER BY ts
    """)
    buckets: dict[int, dict] = {}
    for r in rows:
        b = buckets.setdefault(int(r["ts"]), {"ts": int(r["ts"]), "bytes_sent": 0, "bytes_recv": 0})
        key = "bytes_sent" if r["m"] == "net.bytes_sent" else "bytes_recv"
        b[key] = int(r["bytes"])
    return [buckets[ts] for ts in sorted(buckets)]

def _stats_breakdown(key: str, hours: int = 24) -> dict:
    """Sum of sent-byte deltas grouped by a time-series attribute (category/company)."""
    assert key in ("category", "company")  # internal keys only — never user input
    cutoff = int((time.time() - hours * 3600) * 1000)
    rows = _ch_rows(f"""
        SELECT tv.attrs['{key}'] AS k, sum(sv.d) AS bytes
        FROM (
          SELECT fingerprint, max(value) - min(value) AS d
          FROM signoz_metrics.samples_v4
          WHERE metric_name = 'net.bytes_sent' AND unix_milli > {cutoff}
          GROUP BY fingerprint
        ) sv
        INNER JOIN (
          SELECT fingerprint, argMax(attrs, unix_milli) AS attrs
          FROM signoz_metrics.time_series_v4
          WHERE metric_name = 'net.bytes_sent' GROUP BY fingerprint
        ) tv ON sv.fingerprint = tv.fingerprint
        GROUP BY k ORDER BY bytes DESC
    """)
    return {str(r["k"]): int(r["bytes"]) for r in rows if r.get("k")}

def _stats_top_domains(minutes: int = 15, limit: int = 8) -> list:
    """Destinations this host is talking to right now, with geo hints."""
    cutoff = int((time.time() - minutes * 60) * 1000)
    rows = _ch_rows(f"""
        SELECT tv.attrs['remote_domain'] AS domain,
               any(tv.attrs['category']) AS category,
               any(tv.attrs['company']) AS company,
               sum(sv.d) AS bytes
        FROM (
          SELECT fingerprint, max(value) - min(value) AS d
          FROM signoz_metrics.samples_v4
          WHERE metric_name = 'net.bytes_sent' AND unix_milli > {cutoff}
          GROUP BY fingerprint
        ) sv
        INNER JOIN (
          SELECT fingerprint, argMax(attrs, unix_milli) AS attrs
          FROM signoz_metrics.time_series_v4
          WHERE metric_name = 'net.bytes_sent' GROUP BY fingerprint
        ) tv ON sv.fingerprint = tv.fingerprint
        GROUP BY domain ORDER BY bytes DESC LIMIT {int(limit)}
    """)
    out = []
    for r in rows:
        domain = str(r["domain"])
        ip = domain if _is_ip(domain) else (None if domain in ("localhost", "lan", "unknown") else _resolve(domain))
        geo = geo_for_ip(ip) if ip else (geo_for_domain_hint(domain) if domain in ("localhost", "lan") else None)
        out.append({"domain": domain, "category": str(r["category"]),
                    "company": str(r["company"]), "bytes": int(r["bytes"]),
                    "ip": ip, "geo": geo})
    return out

def _stats_totals() -> dict:
    """Headline counters.

    bytes_24h is a TRUE 24h increase (PromQL increase()-style): per-series sum
    of positive counter deltas via lagInFrame, so agent restarts (in-memory
    counters resetting inside an existing series) can no longer make the stat
    read as a lifetime cumulative total — the old max(value)-min(value) form
    recovered pre-restart lifetime peaks (~806GB bug).

    Scope: OFF-MACHINE traffic only (loopback/LAN series excluded). The
    console's story is "where your data GOES" — bytes that never left the
    host (incl. the 127.0.0.1 demo vampire) would otherwise dominate the
    headline number by three orders of magnitude.
    """
    cutoff24 = int((time.time() - 24 * 3600) * 1000)
    b = _ch_rows(f"""
        SELECT sum(inc) AS bytes FROM (
          SELECT fingerprint, metric_name, if(diff > 0, diff, 0) AS inc
          FROM (
            SELECT fingerprint, metric_name, unix_milli, value,
                   value - lagInFrame(value, 1, value) OVER
                     (PARTITION BY fingerprint, metric_name ORDER BY unix_milli) AS diff
            FROM signoz_metrics.samples_v4
            WHERE metric_name IN ('net.bytes_sent','net.bytes_recv')
              AND unix_milli > {cutoff24}
          )
          WHERE fingerprint IN (
            SELECT fingerprint FROM signoz_metrics.time_series_v4
            WHERE metric_name IN ('net.bytes_sent','net.bytes_recv')
              AND attrs['category'] != 'local'
              AND attrs['remote_domain'] NOT IN ('localhost','lan')
          )
        )
    """)
    procs = _ch_rows(f"""
        SELECT count(DISTINCT tv.attrs['process_name']) AS n
        FROM signoz_metrics.time_series_v4 tv
        WHERE tv.metric_name = 'net.bytes_sent' AND tv.fingerprint IN (
          SELECT DISTINCT fingerprint FROM signoz_metrics.samples_v4
          WHERE metric_name = 'net.bytes_sent' AND unix_milli > {cutoff24}
        )
    """)
    with lock:
        verdicts = len(history)
        fixed = sum(1 for h in history if h.get("fix_status") == "fixed")
        threats = sum(1 for h in history if h.get("risk") in ("RED", "YELLOW"))
    return {"bytes_24h": int(b[0]["bytes"] or 0) if b else 0,
            "processes_seen": int(procs[0]["n"] or 0) if procs else 0,
            "verdicts": verdicts, "threats": threats, "fixed": fixed}

@app.get("/api/stats")
def api_stats(demo: int = 0):
    """Live visualization bundle for Console v2. Cached ~2s. ?demo=1 -> synthetic."""
    if demo:
        return _demo_stats()
    now = time.time()
    if _STATS_CACHE["data"] and now - _STATS_CACHE["ts"] < _STATS_TTL:
        return _STATS_CACHE["data"]
    data = {
        "ts": now,
        "bandwidth_series": _stats_bandwidth(30),
        "by_category": _stats_breakdown("category", 24),
        "by_company": _stats_breakdown("company", 24),
        "top_domains": _stats_top_domains(15, 8),
        "totals": _stats_totals(),
        "blocked": {d: v["ips"] for d, v in BLOCKED_DOMAINS.items()},
    }
    _STATS_CACHE["ts"] = now
    _STATS_CACHE["data"] = data
    return data

# ────────────────────────── DEMO MODE (synthetic data for judges) ──────────────────────────
# Enabled per-request with ?demo=1 — the console toggle lives in localStorage.
# Lets judges explore the full UI without running the capture agent.
# LLM endpoints (/chat, /api/explain) stay real; only the telemetry is fake.
_DEMO_FIXES: dict[str, str] = {}  # demo item id -> simulated remediation outcome
_DEMO_WAVE = [0.30, 0.42, 0.55, 0.72, 0.88, 1.0, 0.94, 0.78, 0.60, 0.45, 0.36, 0.50]

def _demo_stats() -> dict:
    """Synthetic /api/stats payload: same schema as the live one."""
    now = time.time()
    series = []
    for i in range(30):
        w = _DEMO_WAVE[i % len(_DEMO_WAVE)]
        series.append({
            "ts": int(now) - (29 - i) * 60,
            "bytes_sent": int(38_000_000 + 64_000_000 * w),
            "bytes_recv": int(95_000_000 + 150_000_000 * w),
        })
    top_domains = [
        {"domain": "cloudfront.net", "category": "cdn", "company": "Amazon",
         "bytes": 512_000_000, "ip": "18.160.46.4",
         "geo": {"country": "United States", "city": "Seattle (Amazon)", "lat": 47.6062, "lon": -122.3321}},
        {"domain": "googlevideo.com", "category": "streaming", "company": "Google",
         "bytes": 384_000_000, "ip": "142.250.72.14",
         "geo": {"country": "United States", "city": "Mountain View (Google)", "lat": 37.3861, "lon": -122.0839}},
        {"domain": "nflxvideo.net", "category": "streaming", "company": "Netflix",
         "bytes": 296_000_000, "ip": "45.57.90.1",
         "geo": {"country": "United States", "city": "Hillsboro (Netflix)", "lat": 45.5234, "lon": -122.9890}},
        {"domain": "windowsupdate.com", "category": "os-updates", "company": "Microsoft",
         "bytes": 187_000_000, "ip": "20.90.136.1",
         "geo": {"country": "United States", "city": "Redmond (Microsoft)", "lat": 47.6740, "lon": -122.1215}},
        {"domain": "spotify.com", "category": "streaming", "company": "Spotify",
         "bytes": 143_000_000, "ip": "35.186.224.25",
         "geo": {"country": "Sweden", "city": "Stockholm (Spotify)", "lat": 59.3293, "lon": 18.0686}},
        {"domain": "doubleclick.net", "category": "ads", "company": "Google",
         "bytes": 42_000_000, "ip": "142.250.80.46",
         "geo": {"country": "United States", "city": "Mountain View (Google)", "lat": 37.3861, "lon": -122.0839}},
        {"domain": "facebook.com", "category": "tracking", "company": "Meta",
         "bytes": 28_000_000, "ip": "157.240.2.35",
         "geo": {"country": "United States", "city": "Menlo Park (Meta)", "lat": 37.4529, "lon": -122.1817}},
        {"domain": "google-analytics.com", "category": "tracking", "company": "Google",
         "bytes": 19_000_000, "ip": "142.250.65.78",
         "geo": {"country": "United States", "city": "Mountain View (Google)", "lat": 37.3861, "lon": -122.0839}},
    ]
    return {
        "ts": now,
        "bandwidth_series": series,
        "by_category": {"cdn": 524_000_000, "streaming": 823_000_000, "os-updates": 187_000_000,
                        "ads": 42_000_000, "tracking": 47_000_000, "unknown": 31_000_000},
        "by_company": {"Google": 445_000_000, "Netflix": 296_000_000, "Amazon": 524_000_000,
                       "Microsoft": 187_000_000, "Spotify": 143_000_000, "Meta": 28_000_000},
        "top_domains": top_domains,
        "totals": {"bytes_24h": 1_654_000_000, "processes_seen": 14,
                   "verdicts": 3, "threats": 1, "fixed": len(_DEMO_FIXES)},
        "blocked": {},
        "demo": True,
    }

def _demo_report() -> dict:
    """Synthetic /report payload: three plausible verdicts on fake processes."""
    now = time.time()
    items = [
        {"id": "demo-001", "ts": now - 11 * 60,
         "alert_name": "Astrid: Background drain detected",
         "process_name": "svchost.exe",
         "explanation": "This Windows service is uploading about 40 MB an hour to other PCs on the "
                        "internet. That's Delivery Optimization — Microsoft sharing Windows updates "
                        "from your machine to strangers. It isn't malware, but it's spending your "
                        "bandwidth on someone else's updates.",
         "risk": "YELLOW", "risk_reason": "Wasteful peer-to-peer uploads, not malicious.",
         "action": "disable_delivery_optimization", "action_params": {}},
        {"id": "demo-002", "ts": now - 8 * 60,
         "alert_name": "Astrid: Tracker spotted",
         "process_name": "chrome.exe",
         "explanation": "Chrome is talking to doubleclick.net, Google's advertising network. Every "
                        "page you visit reports back which ads you saw. It's normal web traffic, but "
                        "you can cut it off with one click.",
         "risk": "GREEN", "risk_reason": "Well-known ad domain, small volume.",
         "action": "block_domain", "action_params": {"domain": "doubleclick.net"}},
        {"id": "demo-003", "ts": now - 3 * 60,
         "alert_name": "Astrid: Bandwidth spike",
         "process_name": "spotify.exe",
         "explanation": "Spotify is pulling music from Spotify's servers in Stockholm at a steady "
                        "stream rate. That's exactly what a music app should be doing.",
         "risk": "GREEN", "risk_reason": "Expected streaming traffic.",
         "action": "ignore", "action_params": {}},
    ]
    for it in items:
        if it["id"] in _DEMO_FIXES:
            it["outcome"] = _DEMO_FIXES[it["id"]]
            it["fix_status"] = "fixed"
    return {"analyzed": len(items), "items": items, "demo": True}

def _demo_execute_outcome(action: str, proc: str, domain: str) -> str:
    if action == "kill_process":
        return f"[demo] killed '{proc}' (pid 4213)"
    if action == "block_domain":
        return f"[demo] blocked {domain or 'doubleclick.net'} (2 IPs) via firewall"
    if action == "disable_delivery_optimization":
        return "[demo] Delivery Optimization disabled via policy"
    if action == "set_metered":
        return "[demo] connection set to metered"
    return f"[demo] dismissed '{proc}' — nothing to do"

# ────────────────────────── /api/explain ──────────────────────────
DOMAIN_EXPLAIN = {
    "doubleclick.net": "DoubleClick is an advertising network owned by Google. It serves ads on websites and tracks what you browse across the internet to target those ads at you.",
    "googlesyndication.com": "This is part of Google Ads. Websites load ads from this domain, and it reports which ads you saw back to Google.",
    "adservice.google.com": "A Google advertising server. It delivers ads to pages you visit and measures which ones you interact with.",
    "amazon-adsystem.com": "Amazon's advertising network. It tracks your browsing so Amazon can show you targeted product ads.",
    "ads.yahoo.com": "Yahoo's ad server. It delivers advertisements and tracks your activity across sites that use Yahoo ads.",
    "advertising.com": "A long-running online ad network (now part of Yahoo/AOL). It serves ads and builds a profile of your browsing habits.",
    "google-analytics.com": "Google Analytics — the most common website tracker. Sites use it to count visitors and record what you do on their pages.",
    "googletagmanager.com": "Google Tag Manager loads other tracking and advertising scripts onto websites. It isn't a tracker itself, but it enables many.",
    "segment.io": "Segment is a data-collection service. Apps send it a record of everything you do, and it forwards that data to other analytics and marketing tools.",
    "segment.com": "Segment is a data-collection service. Apps send it a record of everything you do, and it forwards that data to other analytics and marketing tools.",
    "mixpanel.com": "Mixpanel is a product-analytics tracker. It records the buttons you click and features you use inside apps and websites.",
    "hotjar.com": "Hotjar records how people use websites — mouse movements, scrolling, and sometimes full session replays.",
    "fullstory.com": "FullStory captures detailed session recordings of what you do on a website so the site's owners can watch them later.",
    "telemetry.mozilla.org": "Mozilla Firefox's usage-reporting server. It receives anonymous statistics about how the browser is performing and being used.",
    "app-measurement.com": "Part of Google Firebase Analytics. Mobile apps use it to report how you use them back to Google.",
    "cloudfront.net": "Amazon CloudFront is a content delivery network. Websites use it to load images, videos, and files quickly from servers near you. Usually harmless.",
    "akamaized.net": "Akamai is one of the largest content delivery networks. A huge share of normal web traffic flows through it. Usually harmless.",
    "fastly.net": "Fastly is a content delivery network used by many major sites to serve content quickly. Usually harmless.",
    "cloudflare.com": "Cloudflare provides security and content delivery for a large fraction of the internet. Traffic here is usually normal.",
    "jsdelivr.net": "jsDelivr is a free content delivery network for open-source code libraries. Usually harmless.",
    "windowsupdate.com": "Microsoft's Windows Update service. Your PC downloads security patches and system updates from here. Normal and important.",
    "update.microsoft.com": "Microsoft's update servers. This is how Windows and Office download updates. Normal traffic.",
    "archive.ubuntu.com": "The official Ubuntu software archive. Your system downloads package updates from here. Normal.",
    "security.ubuntu.com": "Ubuntu's security-update server. Important, expected system traffic.",
    "netflix.com": "Netflix's servers. This is video streaming and app traffic for the Netflix service.",
    "nflxvideo.net": "Netflix's video-delivery network. The actual movies and shows stream from these servers.",
    "youtube.com": "YouTube, owned by Google. Video streaming and related app traffic.",
    "googlevideo.com": "Google's video-delivery network. YouTube videos actually stream from these servers.",
    "spotify.com": "Spotify's music-streaming servers. Normal if you use Spotify.",
    "facebook.com": "Meta's Facebook service. Also used to track you across other websites via embedded Like buttons and pixels.",
    "fbcdn.net": "Facebook's content delivery network — photos and videos from Facebook/Instagram load from here.",
    "gstatic.com": "Google's static-content server. Fonts, scripts, and cached content load from here on most websites. Usually harmless.",
    "google.com": "Google's main servers — search, Gmail, and many embedded services across the web.",
    "microsoft.com": "Microsoft's servers. Normal if you use Windows, Office, or other Microsoft services.",
    "localhost": "This is your own machine talking to itself. Completely normal — many programs use local connections to communicate internally.",
    "lan": "A device on your local network (your home or office), not the internet. Usually another computer, router, or printer nearby.",
    "unknown": "This destination could not be identified. That can be normal, but unidentified destinations receiving lots of data are worth a closer look.",
    "internet-census.org": "A research project that scans the entire internet to map devices. It probes machines — it isn't attacking, but you never asked for it either.",
    "awsglobalaccelerator.com": "Part of Amazon Web Services. Companies route traffic through it to reach Amazon's network faster. Usually normal cloud traffic.",
    "linodeusercontent.com": "A cloud server hosted at Linode (Akamai). Could be anything — someone's server, a VPN endpoint, or a scanner. Worth checking what connects to it.",
    "compute-1.amazonaws.com": "An Amazon AWS cloud server in the US-East region. Many services run on AWS, so this is often normal — but it's just 'someone's server'.",
    "ovh.ca": "A cloud server hosted at OVH in Canada. Generic hosting — could be anything from a game server to a scanner.",
}
_EXPLAIN_CACHE: dict[str, dict] = {}
_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,98}[a-z0-9]$", re.I)

@app.get("/api/explain")
def api_explain(domain: str = ""):
    """Plain-English explanation of a domain. Static table first, LLM fallback, cached."""
    d = domain.strip().lower().rstrip(".")
    cat, company = classify_domain(d) if d else ("unknown", "unknown")
    if not d or not _DOMAIN_RE.match(d):
        return {"domain": domain, "explanation": "That doesn't look like a valid domain name.",
                "category": "unknown", "company": "unknown"}
    if d in DOMAIN_EXPLAIN:
        return {"domain": d, "explanation": DOMAIN_EXPLAIN[d], "category": cat,
                "company": company, "source": "builtin"}
    if d in _EXPLAIN_CACHE:
        return {**_EXPLAIN_CACHE[d], "source": "cache"}
    try:
        resp = llm.chat.completions.create(
            model=NIM_MODEL,
            messages=[{"role": "system", "content":
                       "You explain internet domains to non-technical users. Answer in 1-2 "
                       "plain sentences: who owns it, what it does, and whether it's usually "
                       "safe. No jargon, no markdown."},
                      {"role": "user", "content": f"What is {d}?"}],
            temperature=0.3, max_tokens=120, timeout=25,
        )
        text = resp.choices[0].message.content.strip()
    except Exception as e:
        text = f"{d} — couldn't look this one up right now ({type(e).__name__}). If it's receiving a lot of your data, ask Astrid in the chat."
    item = {"domain": d, "explanation": text, "category": cat, "company": company}
    _EXPLAIN_CACHE[d] = item
    return {**item, "source": "llm"}

# ────────────────────────── /api/geo ──────────────────────────
# This machine: EC2 us-east-1 (N. Virginia) — arcs originate here.
HOME_LAT, HOME_LON = 39.0438, -77.4874

_CF = ("United States", "San Francisco (Cloudflare)", 37.7749, -122.4194)
_GOO = ("United States", "Mountain View (Google)", 37.3861, -122.0839)
_AWS_E = ("United States", "N. Virginia (AWS us-east-1)", 39.0438, -77.4874)
GEO_EXACT = {
    "8.8.8.8": _GOO, "8.8.4.4": _GOO,
    "1.1.1.1": ("United States", "San Francisco (Cloudflare DNS)", 37.7749, -122.4194),
    "1.0.0.1": ("United States", "San Francisco (Cloudflare DNS)", 37.7749, -122.4194),
    "9.9.9.9": ("United States", "Berkeley (Quad9 DNS)", 37.8717, -122.2728),
    "160.79.104.10": ("United States", "San Francisco (Anthropic)", 37.7749, -122.4194),
    "75.2.113.119": _AWS_E,
    "104.18.28.226": _CF, "104.18.29.226": _CF,
    "162.159.130.234": _CF, "162.159.133.234": _CF, "162.159.135.234": _CF,
}
GEO_PREFIX = [  # ordered — first match wins
    ("104.1", _CF), ("104.2", _CF), ("162.158.", _CF), ("162.159.", _CF),
    ("172.64.", _CF), ("172.67.", _CF), ("173.245.", _CF), ("188.114.", _CF), ("198.41.", _CF),
    ("142.250.", _GOO), ("172.217.", _GOO), ("216.58.", _GOO), ("74.125.", _GOO),
    ("151.101.", ("United States", "San Francisco (Fastly)", 37.7749, -122.4194)),
    ("160.79.", ("United States", "San Francisco (Anthropic)", 37.7749, -122.4194)),
    ("13.", _AWS_E), ("3.", _AWS_E), ("34.", ("United States", "Google Cloud", 37.3861, -122.0839)),
    ("44.", _AWS_E), ("52.", _AWS_E), ("54.", _AWS_E), ("18.", _AWS_E),
    ("20.", ("United States", "Microsoft Azure", 47.6062, -122.3321)),
    ("40.", ("United States", "Microsoft Azure", 47.6062, -122.3321)),
    ("157.55.", ("United States", "Redmond (Microsoft)", 47.6740, -122.1215)),
    ("207.46.", ("United States", "Redmond (Microsoft)", 47.6740, -122.1215)),
    ("140.82.", ("United States", "San Francisco (GitHub)", 37.7749, -122.4194)),
    ("185.199.", ("United States", "San Francisco (GitHub Pages)", 37.7749, -122.4194)),
]
PTR_HINTS = [  # reverse-DNS substring -> geo
    ("ovh.ca", ("Canada", "Beauharnois (OVH)", 45.3151, -73.8779)),
    ("compute-1.amazonaws.com", _AWS_E),
    ("awsglobalaccelerator.com", _AWS_E),
    ("us-west-2.compute.amazonaws.com", ("United States", "Oregon (AWS us-west-2)", 45.5234, -122.6762)),
    ("us-east-2.compute.amazonaws.com", ("United States", "Ohio (AWS us-east-2)", 39.9612, -82.9988)),
    ("eu-west-1.compute.amazonaws.com", ("Ireland", "Dublin (AWS eu-west-1)", 53.3498, -6.2603)),
    ("eu-central-1.compute.amazonaws.com", ("Germany", "Frankfurt (AWS eu-central-1)", 50.1109, 8.6821)),
    ("internet-census.org", ("Netherlands", "Amsterdam (internet census scanner)", 52.3676, 4.9041)),
    ("linodeusercontent.com", ("United States", "Linode cloud", 39.8283, -98.5795)),
    ("akamaitechnologies.com", ("United States", "Akamai CDN", 42.3601, -71.0589)),
]
TLD_GEO = {  # country-TLD fallback -> capital-ish coords
    "ca": ("Canada", "", 45.4215, -75.6972), "de": ("Germany", "", 52.5200, 13.4050),
    "fr": ("France", "", 48.8566, 2.3522), "uk": ("United Kingdom", "", 51.5074, -0.1278),
    "nl": ("Netherlands", "", 52.3676, 4.9041), "au": ("Australia", "", -33.8688, 151.2093),
    "jp": ("Japan", "", 35.6762, 139.6503), "in": ("India", "", 28.6139, 77.2090),
    "br": ("Brazil", "", -23.5505, -46.6333), "sg": ("Singapore", "", 1.3521, 103.8198),
    "se": ("Sweden", "", 59.3293, 18.0686), "ch": ("Switzerland", "", 46.8182, 8.2275),
    "ie": ("Ireland", "", 53.3498, -6.2603), "ru": ("Russia", "", 55.7558, 37.6173),
}
_GEO_CACHE: dict[str, dict] = {}

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _local_geo(city: str) -> dict:
    return {"country": "Local", "city": city, "lat": HOME_LAT, "lon": HOME_LON, "local": True}

def geo_for_domain_hint(domain: str) -> dict:
    return _local_geo("this machine" if domain == "localhost" else "LAN")

def geo_for_ip(ip: str) -> dict:
    """Offline geolocation: curated table -> prefix -> PTR heuristics -> Unknown."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    res = _geo_uncached(ip)
    _GEO_CACHE[ip] = res
    return res

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]

def _geo_uncached(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            return _local_geo("this machine")
        if any(addr in n for n in _PRIVATE_NETS):  # RFC1918 only — not doc/reserved ranges
            return _local_geo("LAN")
    except ValueError:
        return {"country": "Unknown", "city": "", "lat": None, "lon": None}
    if ip in GEO_EXACT:
        c = GEO_EXACT[ip]
        return {"country": c[0], "city": c[1], "lat": c[2], "lon": c[3]}
    for p, c in GEO_PREFIX:
        if ip.startswith(p):
            return {"country": c[0], "city": c[1], "lat": c[2], "lon": c[3]}
    host = _ptr(ip)
    if host:
        h = host.lower().rstrip(".")
        for sub, c in PTR_HINTS:
            if sub in h:
                return {"country": c[0], "city": c[1], "lat": c[2], "lon": c[3]}
        tld = h.rsplit(".", 1)[-1] if "." in h else ""
        if tld in TLD_GEO:
            c = TLD_GEO[tld]
            return {"country": c[0], "city": c[1], "lat": c[2], "lon": c[3]}
    return {"country": "Unknown", "city": "", "lat": None, "lon": None}

@app.get("/api/geo")
def api_geo(ip: str = ""):
    """Country + city (+lat/lon) for an IP. Fully offline."""
    ip = ip.strip()
    if not _is_ip(ip):
        return {"ip": ip, "country": "Unknown", "city": "", "lat": None, "lon": None}
    return {"ip": ip, **geo_for_ip(ip)}

# ────────────────────────── /api/block-domain ──────────────────────────
BLOCKABLE_CATEGORIES = {"ads", "tracking"}
BLOCKED_DOMAINS: dict[str, dict] = {}  # domain -> {"ips": [...], "ts": ..., "category": ...}

def _iptables(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo", "-n", "iptables", *args],
                          capture_output=True, text=True, timeout=10)

@app.post("/api/block-domain")
async def api_block_domain(request: Request):
    """Firewall-block a domain's IPs (OUTPUT DROP). Ads/tracking only."""
    try:
        body = await request.json()
    except Exception:
        return {"ok": False, "error": "invalid JSON body"}
    domain = str(body.get("domain", "")).strip().lower().rstrip(".")
    if not domain or not _DOMAIN_RE.match(domain):
        return {"ok": False, "error": f"invalid domain '{domain}'"}
    category, company = classify_domain(domain)
    if category not in BLOCKABLE_CATEGORIES:
        return {"ok": False,
                "error": f"refused: '{domain}' is classified '{category}' — only ads/tracking domains can be blocked",
                "category": category}
    if domain in BLOCKED_DOMAINS:
        return {"ok": True, "domain": domain, "ips": BLOCKED_DOMAINS[domain]["ips"],
                "already_blocked": True, "category": category, "company": company}
    # resolve all A records (bounded), then DROP each
    ips: list[str] = []
    try:
        infos = _DNS_POOL.submit(
            lambda: socket.getaddrinfo(domain, None, socket.AF_INET)).result(timeout=2.5)
        ips = sorted({i[4][0] for i in infos})[:8]
    except Exception as e:
        return {"ok": False, "error": f"could not resolve '{domain}': {e}"}
    if not ips:
        return {"ok": False, "error": f"'{domain}' has no IPv4 addresses"}
    added, already, errors = [], [], []
    for ip in ips:
        try:
            if _iptables(["-C", "OUTPUT", "-d", ip, "-j", "DROP"]).returncode == 0:
                already.append(ip)
                continue
            r = _iptables(["-A", "OUTPUT", "-d", ip, "-j", "DROP"])
            if r.returncode == 0:
                added.append(ip)
            else:
                errors.append(f"{ip}: {r.stderr.strip()[:120]}")
        except Exception as e:
            errors.append(f"{ip}: {e}")
    if not added and not already:
        return {"ok": False, "error": "iptables failed for all IPs: " + "; ".join(errors)}
    BLOCKED_DOMAINS[domain] = {"ips": added + already, "ts": time.time(), "category": category}
    print(f"[block-domain] {domain} ({category}/{company}) added={added} already={already} errors={errors}")
    return {"ok": True, "domain": domain, "ips": added + already, "added": added,
            "already": already, "errors": errors, "category": category, "company": company}

# ────────────────────────── BROWSER CONSOLE (v2) ──────────────────────────
# __CONSOLE_HTML_START__
CONSOLE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Astrid — Mission Control</title>
<style>
:root{
  --bg:#070b12; --panel:rgba(15,23,36,.62); --panel2:rgba(19,29,45,.55);
  --border:rgba(148,180,255,.09); --border-hi:rgba(148,180,255,.22);
  --text:#dbe7f4; --dim:#7a8aa0; --dimmer:#4d5c70;
  --green:#2ee6a8; --yellow:#ffc94d; --red:#ff4d5e; --blue:#3fa9f5;
  --mono:ui-monospace,"SF Mono","Cascadia Mono",Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
html{-webkit-text-size-adjust:100%}
body{
  background:var(--bg);color:var(--text);font-family:var(--sans);
  min-height:100vh;padding:14px 16px 40px;max-width:1460px;margin:0 auto;
  background-image:
    radial-gradient(1100px 500px at 85% -10%,rgba(63,169,245,.07),transparent 60%),
    radial-gradient(900px 480px at -10% 110%,rgba(46,230,168,.05),transparent 60%);
}
.mono{font-family:var(--mono);font-variant-numeric:tabular-nums}
.dim{color:var(--dim)}
button{font-family:inherit}
/* ── header ── */
.topbar{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:6px 2px 16px;flex-wrap:wrap}
.brand{font-size:26px;font-weight:800;letter-spacing:.34em;
  background:linear-gradient(92deg,#eaf4ff 20%,#3fa9f5 55%,#2ee6a8 90%);
  -webkit-background-clip:text;background-clip:text;color:transparent}
.brand-sub{display:block;font-size:9px;font-weight:600;letter-spacing:.52em;color:var(--dim);margin-top:2px}
.live-wrap{display:flex;align-items:center;gap:10px;background:var(--panel);border:1px solid var(--border);
  border-radius:999px;padding:8px 16px;backdrop-filter:blur(12px)}
.live-dot{width:9px;height:9px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse 1.6s infinite}
.live-dot.warn{background:var(--yellow);box-shadow:0 0 10px var(--yellow)}
.live-label{font-size:11px;font-weight:700;letter-spacing:.24em;color:var(--green)}
.live-dot.warn+.live-label{color:var(--yellow)}
.bw{font-size:13px;color:var(--dim)}
.bw b{color:var(--text);font-weight:600}
.bw .up{color:var(--red)} .bw .down{color:var(--blue)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.45;transform:scale(.82)}}
/* ── panels ── */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:16px;
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  padding:16px 18px;margin-bottom:14px;
  box-shadow:0 10px 34px rgba(0,0,0,.34),inset 0 1px 0 rgba(255,255,255,.03)}
.panel-title{font-size:13px;font-weight:800;letter-spacing:.22em;color:var(--text);margin-bottom:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.panel-title-sm{font-size:11px;font-weight:800;letter-spacing:.18em;color:var(--dim);margin-bottom:10px;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.panel-sub{font-size:10px;font-weight:600;letter-spacing:.12em;color:var(--dimmer)}
/* ── hero ── */
.hero{padding:18px 20px}
.hero-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:18px;align-items:stretch}
.map-wrap{position:relative;min-height:280px;border-radius:12px;overflow:hidden;
  background:radial-gradient(120% 140% at 50% 0%,rgba(63,169,245,.06),rgba(7,11,18,.2));
  border:1px solid rgba(148,180,255,.06)}
#mapCanvas{position:absolute;inset:0;width:100%;height:100%}
#mapSvg{position:absolute;inset:0;width:100%;height:100%}
.map-legend{position:absolute;left:10px;bottom:8px;display:flex;gap:12px;flex-wrap:wrap;font-size:10px;color:var(--dim)}
.map-legend .lg{display:flex;align-items:center;gap:5px}
.map-legend .dot{width:7px;height:7px;border-radius:50%}
.map-home-tag{position:absolute;font-size:9px;letter-spacing:.14em;color:var(--green);text-shadow:0 0 8px rgba(46,230,168,.8);pointer-events:none}
.domains{display:flex;flex-direction:column;min-width:0}
.domains-head{font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--dimmer);margin-bottom:8px}
.drow{background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:10px 12px;margin-bottom:8px;
  animation:fadeSlide .4s ease both}
.drow-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.dname{font-size:13px;font-weight:600;color:#eaf2fb;word-break:break-all}
.badge{font-size:9px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:var(--c,#7a8aa0);
  border:1px solid var(--c,#7a8aa0);border-radius:999px;padding:2px 8px;opacity:.9;
  box-shadow:0 0 10px color-mix(in srgb,var(--c,#7a8aa0) 26%,transparent)}
.dexpl{font-size:12.5px;line-height:1.45;color:var(--dim);margin-top:6px}
.dmeta{font-size:11px;color:var(--dimmer);margin-top:6px}
.blocked-tag{font-size:10px;font-weight:800;letter-spacing:.1em;color:var(--green);border:1px solid var(--green);
  border-radius:999px;padding:3px 9px;box-shadow:0 0 10px rgba(46,230,168,.35)}
.hero-foot{display:flex;align-items:center;gap:14px;margin-top:6px;flex-wrap:wrap}
.note{font-size:12px;color:var(--dim)}
/* ── buttons ── */
.btn{border:0;border-radius:10px;padding:11px 20px;font-size:14px;font-weight:700;cursor:pointer;
  min-height:44px;color:#06121f;background:linear-gradient(135deg,#59d0ff,#2ee6a8);
  transition:transform .15s ease,box-shadow .25s ease,opacity .25s ease;letter-spacing:.02em}
.btn:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 6px 22px rgba(63,169,245,.35)}
.btn:disabled{opacity:.55;cursor:default}
.btn.danger{background:linear-gradient(135deg,#ff6b7a,#ff9f43);color:#1a0800}
.btn.danger:hover:not(:disabled){box-shadow:0 6px 22px rgba(255,77,94,.4)}
.btn.ghost{background:rgba(148,180,255,.1);color:var(--text);border:1px solid var(--border-hi)}
.btn.xs{padding:5px 12px;min-height:30px;font-size:12px;border-radius:8px}
.btn.fix{width:100%;margin-top:10px}
.btn.fix.done{background:rgba(46,230,168,.14);color:var(--green);border:1px solid var(--green);
  box-shadow:0 0 16px rgba(46,230,168,.3)}
.btn.fix.bad{background:rgba(255,77,94,.12);color:var(--red);border:1px solid var(--red)}
.qb{width:20px;height:20px;min-height:20px;border-radius:50%;border:1px solid var(--border-hi);background:rgba(148,180,255,.08);
  color:var(--dim);font-size:11px;font-weight:800;cursor:pointer;line-height:1;padding:0;flex:none;
  transition:all .2s ease}
.qb:hover{color:var(--blue);border-color:var(--blue);box-shadow:0 0 10px rgba(63,169,245,.4)}
.spin{display:inline-block;width:13px;height:13px;border:2px solid rgba(255,255,255,.25);border-top-color:#fff;
  border-radius:50%;animation:spin .7s linear infinite;vertical-align:-2px;margin-right:7px}
@keyframes spin{to{transform:rotate(360deg)}}
/* ── stats row ── */
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:14px}
.stat{margin-bottom:0;padding:14px 16px}
.stat-label{font-size:9.5px;font-weight:800;letter-spacing:.18em;color:var(--dimmer)}
.bignum{font-size:clamp(24px,3.4vw,38px);font-weight:700;margin-top:6px;letter-spacing:-.01em;
  font-variant-numeric:tabular-nums;text-shadow:0 0 24px rgba(63,169,245,.25)}
.stat-sub{font-size:11px;color:var(--dim);margin-top:4px}
.stat.hot .bignum{color:var(--red);text-shadow:0 0 24px rgba(255,77,94,.45)}
.stat.good .bignum{color:var(--green);text-shadow:0 0 24px rgba(46,230,168,.4)}
/* ── main grid ── */
.main-grid{display:grid;grid-template-columns:1.55fr 1fr;gap:14px;align-items:start}
.feed-panel{min-width:0}
#feed{display:flex;flex-direction:column;gap:10px}
.empty{color:var(--dimmer);text-align:center;padding:34px 0;font-size:13px}
.vcard{background:var(--panel2);border:1px solid var(--border);border-left:3px solid var(--dimmer);
  border-radius:12px;padding:12px 14px;overflow:hidden;
  transition:opacity .3s ease,border-color .3s ease,box-shadow .3s ease}
.vcard.risk-green{border-left-color:var(--green)}
.vcard.risk-yellow{border-left-color:var(--yellow);box-shadow:0 0 18px rgba(255,201,77,.07)}
.vcard.risk-red{border-left-color:var(--red);box-shadow:0 0 22px rgba(255,77,94,.13)}
.vcard.enter{animation:cardIn .45s cubic-bezier(.2,.9,.3,1.2) both,pulseBorder 1.8s ease .1s}
@keyframes cardIn{from{opacity:0;transform:translateY(-14px) scale(.97)}to{opacity:1;transform:none}}
@keyframes pulseBorder{0%,100%{box-shadow:0 0 0 rgba(63,169,245,0)}35%{box-shadow:0 0 26px rgba(63,169,245,.4)}}
.vhead{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.vdot{width:9px;height:9px;border-radius:50%;flex:none}
.risk-green .vdot{background:var(--green);box-shadow:0 0 8px var(--green)}
.risk-yellow .vdot{background:var(--yellow);box-shadow:0 0 8px var(--yellow)}
.risk-red .vdot{background:var(--red);box-shadow:0 0 10px var(--red);animation:pulse 1.4s infinite}
.vrisk{font-size:11px;font-weight:800;letter-spacing:.16em}
.risk-green .vrisk{color:var(--green)} .risk-yellow .vrisk{color:var(--yellow)} .risk-red .vrisk{color:var(--red)}
.vproc{font-size:12.5px;background:rgba(148,180,255,.09);border:1px solid var(--border);border-radius:7px;
  padding:3px 8px;color:#cfe3ff;display:inline-flex;align-items:center;gap:6px}
.vtime{margin-left:auto;font-size:11px;color:var(--dimmer)}
.valert{font-size:12px;font-weight:700;color:var(--blue);letter-spacing:.02em;margin-top:9px}
.vexpl{font-size:13.5px;line-height:1.5;margin-top:5px}
.vreason{font-size:12px;color:var(--yellow);margin-top:6px}
.voutcome{font-size:12px;color:var(--green);margin-top:7px;font-family:var(--mono)}
.voutcome.err{color:var(--red)}
.vcard.fixed{opacity:.62}
.vcard.fixed .vbody{max-height:400px;transition:max-height .35s ease,opacity .3s ease,margin .3s ease}
.vcard.fixed.collapsed .vbody{max-height:0;opacity:0;margin-top:0;overflow:hidden}
.vcard.flash{animation:flashOk .9s ease}
@keyframes flashOk{0%{box-shadow:0 0 0 rgba(46,230,168,0)}30%{box-shadow:0 0 34px rgba(46,230,168,.55)}100%{box-shadow:0 0 0 rgba(46,230,168,0)}}
.vfixed-line{display:none;font-size:11px;color:var(--green);font-family:var(--mono)}
.vcard.fixed.collapsed .vfixed-line{display:block}
/* ── rail ── */
.rail{display:flex;flex-direction:column;min-width:0}
.rail .panel{margin-bottom:14px}
#bwChart{width:100%;height:130px;display:block}
.chart-legend{display:flex;gap:14px;font-size:10.5px;color:var(--dim);margin-top:6px;align-items:center}
.chip{width:10px;height:10px;border-radius:3px;display:inline-block;margin-right:5px;vertical-align:-1px}
.chip.up{background:var(--red)} .chip.down{background:var(--blue)}
.donut-wrap{display:flex;align-items:center;gap:14px}
#donut{width:132px;height:132px;flex:none}
.donut-legend{display:flex;flex-direction:column;gap:5px;font-size:11.5px;color:var(--dim);min-width:0}
.donut-legend .li{display:flex;align-items:center;gap:7px}
.donut-legend .li b{color:var(--text);font-weight:600;margin-left:auto;font-family:var(--mono);font-size:11px}
.recv-row{margin-bottom:9px}
.recv-top{display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;gap:8px}
.recv-name{color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.recv-bytes{color:var(--dim);font-family:var(--mono);font-size:11px;flex:none}
.recv-bar{height:7px;border-radius:99px;background:rgba(148,180,255,.08);overflow:hidden}
.recv-fill{height:100%;border-radius:99px;background:linear-gradient(90deg,#2b6cb0,#3fa9f5);
  width:0%;transition:width .8s cubic-bezier(.2,.8,.25,1);box-shadow:0 0 10px rgba(63,169,245,.45)}
/* ── chat ── */
.chat-panel{display:flex;flex-direction:column}
.chat-log{min-height:150px;max-height:300px;overflow-y:auto;display:flex;flex-direction:column;gap:9px;
  padding:10px;background:rgba(3,6,11,.55);border:1px solid var(--border);border-radius:10px;
  font-family:var(--mono);font-size:12.5px;scrollbar-width:thin}
.msg{line-height:1.5;white-space:pre-wrap;word-break:break-word;animation:fadeSlide .3s ease both}
.msg .who{font-weight:700;margin-right:6px}
.msg.you .who{color:var(--blue)}
.msg.astrid .who{color:var(--green)}
.msg.you{color:#bcd7f5}
.msg.astrid{color:var(--text)}
.typing{display:inline-flex;gap:4px;padding:4px 0}
.typing i{width:6px;height:6px;border-radius:50%;background:var(--green);animation:tp 1s infinite}
.typing i:nth-child(2){animation-delay:.18s}.typing i:nth-child(3){animation-delay:.36s}
@keyframes tp{0%,100%{opacity:.25;transform:translateY(0)}50%{opacity:1;transform:translateY(-3px)}}
.chat-row{display:flex;gap:8px;margin-top:10px}
.chat-row input{flex:1;background:rgba(3,6,11,.6);border:1px solid var(--border);border-radius:10px;
  color:var(--text);padding:11px 13px;font-size:14px;font-family:var(--mono);outline:none;min-height:44px;
  transition:border-color .2s ease,box-shadow .2s ease}
.chat-row input:focus{border-color:var(--blue);box-shadow:0 0 14px rgba(63,169,245,.25)}
@keyframes fadeSlide{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
/* ── how to ── */
.howto{cursor:pointer}
.howto summary{font-size:12px;font-weight:800;letter-spacing:.2em;color:var(--dim);list-style:none;display:flex;align-items:center;gap:8px}
.howto summary::before{content:"▸";transition:transform .25s ease;color:var(--blue)}
.howto[open] summary::before{transform:rotate(90deg)}
.howto p{font-size:13.5px;line-height:1.65;color:var(--dim);margin-top:12px;max-width:70ch}
.howto b{color:var(--text)}
.foot{text-align:center;color:var(--dimmer);font-size:11px;letter-spacing:.08em;margin-top:18px}
/* ── header controls: view toggle + demo mode ── */
.hdr-controls{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.seg{display:flex;background:var(--panel);border:1px solid var(--border);border-radius:999px;padding:3px;backdrop-filter:blur(12px)}
.seg-btn{border:0;background:transparent;color:var(--dim);font-size:10.5px;font-weight:800;letter-spacing:.16em;
  padding:7px 14px;border-radius:999px;cursor:pointer;transition:all .2s ease;min-height:30px}
.seg-btn:hover{color:var(--text)}
.seg-btn.active{background:linear-gradient(135deg,rgba(63,169,245,.28),rgba(46,230,168,.28));color:#eaf4ff;
  box-shadow:0 0 14px rgba(63,169,245,.25)}
.demo-toggle{display:flex;align-items:center;gap:8px;cursor:pointer;background:var(--panel);
  border:1px solid var(--border);border-radius:999px;padding:6px 12px;backdrop-filter:blur(12px);
  user-select:none;transition:border-color .2s ease,box-shadow .2s ease}
.demo-toggle input{display:none}
.dt-track{width:30px;height:16px;border-radius:999px;background:rgba(148,180,255,.12);position:relative;
  transition:background .25s ease;flex:none}
.dt-thumb{position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:var(--dim);
  transition:transform .25s ease,background .25s ease}
.demo-toggle.on{border-color:rgba(255,201,77,.45);box-shadow:0 0 14px rgba(255,201,77,.18)}
.demo-toggle.on .dt-track{background:rgba(255,201,77,.3)}
.demo-toggle.on .dt-thumb{transform:translateX(14px);background:var(--yellow)}
.dt-label{font-size:10px;font-weight:800;letter-spacing:.18em;color:var(--dim)}
.demo-toggle.on .dt-label{color:var(--yellow)}
/* ── SigNoz embedded view ── */
.signoz-note{font-size:12.5px;color:var(--dim);margin-bottom:12px;line-height:1.5}
.signoz-note b{color:var(--text)}
#signozFrame{width:100%;height:78vh;min-height:420px;border:1px solid var(--border);border-radius:12px;
  background:#0b0f17;display:block}
.demo-banner{display:none;font-size:10px;font-weight:800;letter-spacing:.2em;color:var(--yellow);
  border:1px solid rgba(255,201,77,.4);border-radius:999px;padding:4px 12px;margin-left:10px;
  box-shadow:0 0 14px rgba(255,201,77,.2)}
body.demo .demo-banner{display:inline-block}
body.demo .live-label{color:var(--yellow)}
/* ── responsive ── */
@media (max-width:1020px){
  .hero-grid{grid-template-columns:1fr}
  .main-grid{grid-template-columns:1fr}
  .stats-row{grid-template-columns:repeat(2,1fr)}
  .map-wrap{min-height:230px}
}
@media (max-width:430px){
  body{padding:10px 10px 30px}
  .brand{font-size:21px}
  .stats-row{grid-template-columns:repeat(2,1fr);gap:10px}
  .bignum{font-size:24px}
}
</style>
</head>
<body>
<noscript><p style="padding:20px;text-align:center">Astrid Console needs JavaScript.</p></noscript>

<header class="topbar">
  <div class="brand">ASTRID<span class="brand-sub">MISSION CONTROL</span></div>
  <div class="hdr-controls">
    <div class="seg" role="tablist" aria-label="View selector">
      <button id="viewAstridBtn" class="seg-btn active" title="AI-powered console">ASTRID</button>
      <button id="viewSignozBtn" class="seg-btn" title="Raw SigNoz metrics">SIGNOZ</button>
    </div>
    <label class="demo-toggle" id="demoToggle" title="Demo Mode: synthetic data so judges can explore without the agent">
      <input type="checkbox" id="demoCheck">
      <span class="dt-track"><span class="dt-thumb"></span></span>
      <span class="dt-label">DEMO MODE</span>
    </label>
    <div class="live-wrap">
      <span id="liveDot" class="live-dot"></span><span class="live-label" id="liveLabel">LIVE</span><span class="demo-banner">SYNTHETIC DATA</span>
      <span class="bw mono"><span class="up">▲</span> <b id="bwUp">—</b> &nbsp;<span class="down">▼</span> <b id="bwDown">—</b></span>
    </div>
  </div>
</header>

<section id="signozView" class="panel" style="display:none">
  <div class="panel-title">SIGNOZ — RAW METRICS</div>
  <p class="signoz-note"><b>SigNoz shows raw metrics. Astrid explains them.</b>
  This is the observability backend Astrid watches — every chart here is real telemetry from this machine.
  Flip back to the Astrid view for plain-English verdicts and one-click fixes.</p>
  <iframe id="signozFrame" src="about:blank" title="SigNoz raw metrics dashboard"></iframe>
</section>

<div id="astridView">

<section class="panel hero">
  <div class="panel-title">WHERE YOUR DATA GOES
    <button class="qb" data-q="What does the 'Where Your Data Goes' map show me?">?</button>
  </div>
  <div class="hero-grid">
    <div class="map-wrap">
      <canvas id="mapCanvas"></canvas>
      <svg id="mapSvg" viewBox="0 0 600 320" preserveAspectRatio="xMidYMid meet"></svg>
      <div class="map-legend" id="mapLegend"></div>
    </div>
    <div class="domains">
      <div class="domains-head">TOP DESTINATIONS · LAST 15 MIN</div>
      <div id="domainList"><div class="empty">listening…</div></div>
    </div>
  </div>
  <div class="hero-foot">
    <button id="blockAllBtn" class="btn danger">⛔ Block All Trackers</button>
    <span id="blockAllNote" class="note"></span>
  </div>
</section>

<section class="stats-row">
  <div class="panel stat"><div class="stat-label">DATA MONITORED · 24H</div><div class="bignum mono" id="stBytes">0</div><div class="stat-sub">sent + received</div></div>
  <div class="panel stat"><div class="stat-label">PROCESSES WATCHED</div><div class="bignum mono" id="stProcs">0</div><div class="stat-sub">seen on the network</div></div>
  <div class="panel stat hot"><div class="stat-label">THREATS FLAGGED</div><div class="bignum mono" id="stThreats">0</div><div class="stat-sub">yellow + red verdicts</div></div>
  <div class="panel stat good"><div class="stat-label">FIXED</div><div class="bignum mono" id="stFixed">0</div><div class="stat-sub">remediations applied</div></div>
</section>

<main class="main-grid">
  <section class="panel feed-panel">
    <div class="panel-title">LIVE VERDICTS <span class="panel-sub" id="verdictCount"></span></div>
    <div id="feed"><div class="empty">No alerts analyzed yet — Astrid is watching.</div></div>
  </section>

  <aside class="rail">
    <div class="panel">
      <div class="panel-title-sm">BANDWIDTH
        <span class="mono dim">net.bytes_sent</span><button class="qb" data-q="What does net.bytes_sent mean?">?</button>
        <span class="mono dim">net.bytes_recv</span><button class="qb" data-q="What does net.bytes_recv mean?">?</button>
      </div>
      <svg id="bwChart" viewBox="0 0 340 130" preserveAspectRatio="none"></svg>
      <div class="chart-legend"><span><span class="chip up"></span>upload</span><span><span class="chip down"></span>download</span><span class="dim" id="bwScale"></span></div>
    </div>

    <div class="panel">
      <div class="panel-title-sm">DATA BY CATEGORY
        <button class="qb" data-q="What do the data categories (ads, tracking, cdn…) mean?">?</button>
      </div>
      <div class="donut-wrap">
        <svg id="donut" viewBox="0 0 140 140"></svg>
        <div id="donutLegend" class="donut-legend"></div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title-sm">TOP RECEIVERS · 24H
        <button class="qb" data-q="What does the Top Receivers list show?">?</button>
      </div>
      <div id="receivers"><div class="empty">—</div></div>
    </div>

    <div class="panel chat-panel">
      <div class="panel-title-sm">ASK ASTRID</div>
      <div id="chatLog" class="chat-log">
        <div class="msg astrid"><span class="who">astrid ›</span>Ask me anything about what your machine is doing on the network. Tap the ? buttons anywhere and I'll explain that exact thing.</div>
      </div>
      <div class="chat-row">
        <input id="chatIn" placeholder="what is svc-updater doing?" autocomplete="off">
        <button class="btn" id="chatSend">Send</button>
      </div>
    </div>
  </aside>
</main>

<details class="panel howto">
  <summary>HOW IT WORKS</summary>
  <p><b>Astrid</b> uses <b>SigNoz</b> to collect metrics about your network traffic — every process, every destination, every byte.
  When something unusual happens, SigNoz sends an alert to Astrid's AI.
  The AI explains what's happening in plain English and suggests a fix.
  You can click a button to apply the fix automatically.
  Nothing leaves this machine except the question you ask — the AI's only job is to watch, explain, and act when you say so.</p>
</details>

<footer class="foot">ASTRID · SIGNOZ + LOCAL LLM ANALYST · ALL TELEMETRY STAYS ON THIS MACHINE</footer>
</div><!-- /#astridView -->

<script>
"use strict";
/* ══════════════ config ══════════════ */
const POLL = 3000;
const CAT_COLORS = {ads:"#ff7a45",tracking:"#ff4d5e",cdn:"#3fa9f5","os-updates":"#3ddc84",
                    streaming:"#b085f5",local:"#5c6b7a",unknown:"#e6c34a"};
const RISK_COLOR = {GREEN:"#2ee6a8",YELLOW:"#ffc94d",RED:"#ff4d5e"};
const HOME = {lat:39.0438, lon:-77.4874};   // this machine (EC2 us-east-1)

/* ══════════════ view + demo mode state (persisted) ══════════════ */
const VIEW_KEY = "astrid_view", DEMO_KEY = "astrid_demo";
let DEMO = localStorage.getItem(DEMO_KEY) === "1";
let VIEW = localStorage.getItem(VIEW_KEY) || "astrid";
const demoQS = () => DEMO ? "?demo=1" : "";
function applyView(){
  const signoz = VIEW === "signoz";
  $("astridView").style.display = signoz ? "none" : "";
  $("signozView").style.display = signoz ? "" : "none";
  $("viewAstridBtn").classList.toggle("active", !signoz);
  $("viewSignozBtn").classList.toggle("active", signoz);
  if (signoz && $("signozFrame").src === "about:blank")
    $("signozFrame").src = "http://localhost:8080";
}
function setView(v){ VIEW = v; localStorage.setItem(VIEW_KEY, v); applyView(); }
function applyDemo(){
  document.body.classList.toggle("demo", DEMO);
  $("demoCheck").checked = DEMO;
  $("demoToggle").classList.toggle("on", DEMO);
  $("liveLabel").textContent = DEMO ? "DEMO" : "LIVE";
}
function setDemo(on){
  DEMO = on; localStorage.setItem(DEMO_KEY, on ? "1" : "0");
  applyDemo();
  refreshAll();   // refetch immediately so the switch feels instant
}

/* ══════════════ world map data (120x64 dot grid, lat 83..-58) ══════════════ */
const MAP_ROWS = ["000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000010000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000111110000000000111111100000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000001111111000000011111111111000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000011111111110000011111111111000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000011111111111111111111000011111111111100000000000000000000000000000000000000000000000000000000000000000000", "000001111111111111111111111111111111000011111111111000000000000000111100000000000000000000000000000000000001111110000000", "000011111111111111111111111111111111100011111111110000000000000011111100000000000000000000000000000000001111111111111000", "000001111111111111111111111111111111100001111111000001100000000111111100000000000000000000000000000000111111111111111110", "000001111111111111111111111111111111110000011110000000000000001111111000000000000000000000000000000111111111111111111110", "000000111100011111111111111111111111111000000000000000000000001111110000000000000000000000000000001111111111111111000000", "000000000000000111111111111111111111111100000000000000000010000011100000000000000000000000000000011111111111111100000000", "000000000000000011111111111111111111111110000000000000000010001111000000000000000000000000000000111111111111110000000000", "000000000000000001111111111111111111111110000000000000000110001000000000000000000000000100000001111111111111000000000000", "000000000000000000111111111111111111111110000000000000000000010000000000000000000000011110011111111111111111000000000000", "000000000000000000111111111111111111111110000000000000000001111000000000100000000000111111111111111111111110000000000000", "000000000000000000011111111111111111111100000000000000000001111000000011100000000001111111111111111111111100000000000000", "000000000000000000011111111111111111110000000000000000000001111100000011110010000111111111111111111111110000000000000000", "000000000000000000011111111111111111100000000000000000000111111100000111111100011111111111111111111111100001000000000000", "000000000000000000011111111111111111000000000000000000000111111110011111111100011111111111111111111111100000000000000000", "000000000000000000011111111111111110000000000000000000000111111110011011111100111111111111111111111111000000000000000000", "000000000000000000001111111111111110000000000000000000000000111000000000011111111111111111111111111110000000000000000000", "000000000000000000000111111111111100000000000000000000000011111110000000001111111111111111111111111100001000000000000000", "000000000000000000000011111111111000000000000000000000000111111111111100000111111111111111111111111100000000000000000000", "000000000000000000000001111111001000000000000000000000000111111111111110000001111111111111111111111100000000000000000000", "000000000000000000000001111111000000000000000000000000001111111111111110000000111111111111111111111100000000000000000000", "000000000000000000000000111111000000000000000000000000001111111111111111000000000011111111111111111100000000000000000000", "000000000000000000000000010110000100000000000000000000011111111111111111000000000001111100111111110000000000000000000000", "000000000000000000000000000000000001000000000000000000111111111111111111100000000000111100011111100000000000000000000000", "000000000000000000000000000000000000000000000000000000111111111111111111100000000000111100011111000000000000000000000000", "000000000000000000000000000010100000000000000000000000111111111111111111110000000000111000001111000010000000000000000000", "000000000000000000000000000000010000000000000000000000111111111111111111110000000000011000000111000000000000000000000000", "000000000000000000000000000000001000000000000000000000011111111111111111111100000000011000000110000001000000000000000000", "000000000000000000000000000000000001111000000000000000011111111111111111111110000000011000000010000000000000000000000000", "000000000000000000000000000000000011111100000000000000001111111111111111111100000000000000000010000000000000000000000000", "000000000000000000000000000000000011111110000000000000000000001111111111111100000000000000000000000000000000000000000000", "000000000000000000000000000000000011111111000000000000000000000111111111111000000000000000001000001000000000000000000000", "000000000000000000000000000000000111111111100000000000000000000111111111111000000000000000000100111110000000000000000000", "000000000000000000000000000000000111111111111000000000000000000111111111110000000000000000000110011010001000000000000000", "000000000000000000000000000000000111111111111100000000000000000011111111110000000000000000000011000000000111000000000000", "000000000000000000000000000000000011111111111110000000000000000011111111110000000000000000000001100000000011100000000000", "000000000000000000000000000000000011111111111111000000000000000011111111100000000000000000000000000000000000011000000000", "000000000000000000000000000000000001111111111111000000000000000011111111100000000000000000000000000000000000000000000000", "000000000000000000000000000000000001111111111111000000000000000011111111100000000000000000000000000000011101000000000000", "000000000000000000000000000000000000111111111110000000000000000011111111000100000000000000000000000000111111000000000000", "000000000000000000000000000000000000111111111110000000000000000011111111000110000000000000000000000001111111000000000000", "000000000000000000000000000000000000011111111110000000000000000001111111001100000000000000000000000011111111100000000000", "000000000000000000000000000000000000011111111110000000000000000001111110000100000000000000000000001111111111110000000000", "000000000000000000000000000000000000011111111100000000000000000001111110000100000000000000000000001111111111110000000000", "000000000000000000000000000000000000111111111000000000000000000001111110000000000000000000000000001111111111111000000000", "000000000000000000000000000000000000111111110000000000000000000001111100000000000000000000000000001111111111111000000000", "000000000000000000000000000000000000111111100000000000000000000000111100000000000000000000000000001111111111111000000000", "000000000000000000000000000000000000111111000000000000000000000000111100000000000000000000000000001111001111111000000000", "000000000000000000000000000000000000111110000000000000000000000000000000000000000000000000000000000000000111110000000000", "000000000000000000000000000000000000111110000000000000000000000000000000000000000000000000000000000000000011110000000000", "000000000000000000000000000000000000111100000000000000000000000000000000000000000000000000000000000000000000000000000010", "000000000000000000000000000000000000111000000000000000000000000000000000000000000000000000000000000000000000000000000100", "000000000000000000000000000000000001111000000000000000000000000000000000000000000000000000000000000000000000000000001000", "000000000000000000000000000000000001110000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000110000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"];
const LAT_TOP = 83, LAT_BOT = -58, VW = 600, VH = 320;
function proj(lon, lat){ return [(lon+180)/360*VW, (LAT_TOP-lat)/(LAT_TOP-LAT_BOT)*VH]; }

/* ══════════════ tiny utils ══════════════ */
const $ = id => document.getElementById(id);
function esc(s){ return String(s==null?"":s).replace(/[&<>"]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c])); }
function fmtBytes(n){
  n = +n || 0;
  if (n < 1024) return n.toFixed(0)+" B";
  if (n < 1048576) return (n/1024).toFixed(1)+" KB";
  if (n < 1073741824) return (n/1048576).toFixed(1)+" MB";
  if (n < 1099511627776) return (n/1073741824).toFixed(2)+" GB";
  return (n/1099511627776).toFixed(2)+" TB";
}
function fmtRate(bytesPerSec){ return fmtBytes(bytesPerSec)+"/s"; }
function catColor(c){ return CAT_COLORS[c] || CAT_COLORS.unknown; }
function cssSafe(s){ return String(s).replace(/[^a-z0-9]/gi,"_"); }
function easeOut(t){ return 1-Math.pow(1-t,3); }

/* ══════════════ generic animation tweens ══════════════ */
const rafHandles = new Map();
function tween(key, onFrame, dur){
  if (rafHandles.has(key)) cancelAnimationFrame(rafHandles.get(key));
  const t0 = performance.now();
  function frame(now){
    const t = Math.min(1, (now-t0)/(dur||650));
    onFrame(easeOut(t), t>=1);
    if (t < 1) rafHandles.set(key, requestAnimationFrame(frame));
    else rafHandles.delete(key);
  }
  rafHandles.set(key, requestAnimationFrame(frame));
}

/* ══════════════ count-up numbers ══════════════ */
const statState = {stBytes:0, stProcs:0, stThreats:0, stFixed:0};
function countUp(id, target, fmt){
  const el = $(id), from = statState[id] || 0;
  statState[id] = target;
  if (from === target){ el.textContent = fmt(target); return; }
  tween("cu-"+id, e => { el.textContent = fmt(Math.round(from + (target-from)*e)); }, 800);
}

/* ══════════════ world map ══════════════ */
function drawMapDots(){
  const cv = $("mapCanvas"), dpr = window.devicePixelRatio || 1;
  cv.width = VW*dpr; cv.height = VH*dpr;
  const ctx = cv.getContext("2d");
  ctx.scale(dpr, dpr);
  const cw = VW/120, ch = VH/64;
  let i = 0;
  for (let r=0; r<64; r++){
    const row = MAP_ROWS[r];
    for (let c=0; c<120; c++){
      if (row.charCodeAt(c) === 49){
        // deterministic texture: subtle brightness variance
        const v = ((i*2654435761) >>> 8) % 100;
        ctx.fillStyle = v < 22 ? "#24405f" : (v < 60 ? "#1a2f4a" : "#14253c");
        ctx.beginPath();
        ctx.arc((c+.5)*cw, (r+.5)*ch, cw*0.32, 0, 6.2832);
        ctx.fill();
        i++;
      }
    }
  }
}
function arcPath(x1,y1,x2,y2){
  const dx=x2-x1, dy=y2-y1, d=Math.hypot(dx,dy);
  const lift = Math.min(90, Math.max(18, d*0.28));
  const mx=(x1+x2)/2, my=(y1+y2)/2 - lift;
  return "M "+x1.toFixed(1)+" "+y1.toFixed(1)+" Q "+mx.toFixed(1)+" "+my.toFixed(1)+" "+x2.toFixed(1)+" "+y2.toFixed(1);
}
function renderMap(topDomains){
  const svg = $("mapSvg");
  const [hx, hy] = proj(HOME.lon, HOME.lat);
  let s = "";
  // home crosshair + pulse
  s += '<circle cx="'+hx+'" cy="'+hy+'" r="3.2" fill="#2ee6a8"/>';
  s += '<circle cx="'+hx+'" cy="'+hy+'" r="3.2" fill="none" stroke="#2ee6a8" stroke-width="1"><animate attributeName="r" from="3" to="16" dur="2.2s" repeatCount="indefinite"/><animate attributeName="opacity" from=".8" to="0" dur="2.2s" repeatCount="indefinite"/></circle>';
  s += '<text x="'+(hx+9)+'" y="'+(hy-7)+'" fill="#2ee6a8" font-size="9" letter-spacing="1.5" font-family="ui-monospace,monospace">THIS MACHINE</text>';
  const cats = new Set();
  (topDomains||[]).forEach(d => {
    const g = d.geo;
    if (!g || g.lat == null) return;
    const col = catColor(d.category);
    if (g.local){
      // local traffic: soft ring at home, no arc off-map
      s += '<circle cx="'+hx+'" cy="'+hy+'" r="8" fill="none" stroke="'+col+'" stroke-width="1.2" opacity=".55"><animate attributeName="r" from="6" to="12" dur="1.8s" repeatCount="indefinite"/><animate attributeName="opacity" from=".6" to=".1" dur="1.8s" repeatCount="indefinite"/></circle>';
      return;
    }
    cats.add(d.category);
    const [tx, ty] = proj(g.lon, g.lat);
    const dash = (5 + (d.domain.length % 4));
    s += '<path d="'+arcPath(hx,hy,tx,ty)+'" fill="none" stroke="'+col+'" stroke-width="1.6" opacity=".8" '
       + 'stroke-dasharray="'+dash+' '+(dash+3)+'" stroke-linecap="round">'
       + '<animate attributeName="stroke-dashoffset" from="0" to="-'+(2*dash+3)*4+'" dur="2.6s" repeatCount="indefinite"/></path>';
    s += '<circle cx="'+tx+'" cy="'+ty+'" r="2.6" fill="'+col+'"/>';
    s += '<circle cx="'+tx+'" cy="'+ty+'" r="2.6" fill="none" stroke="'+col+'" stroke-width="1"><animate attributeName="r" from="2.6" to="11" dur="2s" repeatCount="indefinite"/><animate attributeName="opacity" from=".9" to="0" dur="2s" repeatCount="indefinite"/></circle>';
    const label = (g.city || g.country || "").split("(")[0].trim();
    if (label) s += '<text x="'+(tx+7)+'" y="'+(ty+3)+'" fill="'+col+'" font-size="8.5" opacity=".85" font-family="ui-monospace,monospace">'+esc(label.toUpperCase())+'</text>';
  });
  svg.innerHTML = s;
  // legend for categories present + local
  const lg = $("mapLegend");
  const items = [...cats].map(c => '<span class="lg"><span class="dot" style="background:'+catColor(c)+'"></span>'+esc(c)+'</span>');
  items.push('<span class="lg"><span class="dot" style="background:#2ee6a8"></span>this machine</span>');
  lg.innerHTML = items.join("");
}

/* ══════════════ hero: top domains ══════════════ */
const explainCache = {};
let BLOCKED = {};
function fetchExplain(domain){
  if (explainCache[domain]) return;
  explainCache[domain] = true;
  fetch("/api/explain?domain="+encodeURIComponent(domain))
    .then(r => r.json())
    .then(d => {
      explainCache[domain] = d.explanation || "";
      const slot = $("ex-"+cssSafe(domain));
      if (slot) slot.textContent = explainCache[domain];
    })
    .catch(() => { explainCache[domain] = ""; });
}
function renderDomains(list){
  const el = $("domainList");
  const top = (list||[]).slice(0,5);
  if (!top.length){ el.innerHTML = '<div class="empty">no destinations in the last 15 min</div>'; return; }
  el.innerHTML = top.map(d => {
    const col = catColor(d.category);
    const blockable = d.category==="ads" || d.category==="tracking";
    const blocked = !!BLOCKED[d.domain];
    const cached = explainCache[d.domain];
    const expl = (typeof cached === "string" && cached) ? cached : "…";
    const geoTxt = (d.geo && d.geo.country && d.geo.country!=="Unknown")
      ? " · "+esc(d.geo.city ? d.geo.city.replace(/\s*\(.*\)/,"")+", "+d.geo.country : d.geo.country) : "";
    return '<div class="drow">'
      + '<div class="drow-top">'
      +   '<span class="mono dname">'+esc(d.domain)+'</span>'
      +   '<button class="qb" data-q="What is '+esc(d.domain)+' and should I be worried?">?</button>'
      +   '<span class="badge" style="--c:'+col+'">'+esc(d.category)+'</span>'
      +   (blockable
             ? (blocked ? '<span class="blocked-tag">BLOCKED ✓</span>'
                        : '<button class="btn xs danger" data-block="'+esc(d.domain)+'">Block</button>')
             : "")
      + '</div>'
      + '<div class="dexpl" id="ex-'+cssSafe(d.domain)+'">'+esc(expl)+'</div>'
      + '<div class="dmeta mono">'+esc(d.company||"unknown")+' · '+fmtBytes(d.bytes)+" recently"+geoTxt+'</div>'
      + '</div>';
  }).join("");
  top.forEach(d => { if (!explainCache[d.domain]) fetchExplain(d.domain); });
  el.querySelectorAll("[data-block]").forEach(b =>
    b.addEventListener("click", () => blockDomain(b.getAttribute("data-block"), b)));
}
function blockDomain(domain, btn){
  if (DEMO){  // demo mode: simulate locally, never touch the real firewall
    if (btn){ btn.disabled = true; btn.textContent = "Blocking…"; }
    setTimeout(() => {
      BLOCKED[domain] = ["203.0.113.10"];
      if (btn) btn.outerHTML = '<span class="blocked-tag">BLOCKED ✓</span>';
      note("blockAllNote", "[demo] "+domain+" blocked at the firewall (simulated).");
    }, 500);
    return;
  }
  if (btn){ btn.disabled = true; btn.textContent = "Blocking…"; }
  fetch("/api/block-domain", {method:"POST", headers:{"Content-Type":"application/json"},
                              body:JSON.stringify({domain})})
    .then(r => r.json())
    .then(d => {
      if (d.ok){
        BLOCKED[domain] = d.ips || [];
        if (btn) btn.outerHTML = '<span class="blocked-tag">BLOCKED ✓</span>';
        note("blockAllNote", domain+" blocked at the firewall ("+(d.ips||[]).length+" IP"+((d.ips||[]).length===1?"":"s")+").");
      } else {
        if (btn){ btn.disabled = false; btn.textContent = "Block"; }
        note("blockAllNote", "Can't block "+domain+": "+(d.error||"unknown error"));
      }
    })
    .catch(() => { if (btn){ btn.disabled=false; btn.textContent="Block"; } note("blockAllNote","network error while blocking "+domain); });
}
function blockAllTrackers(){
  const btn = $("blockAllBtn");
  const trackers = (LAST_STATS.top_domains||[]).filter(d =>
    (d.category==="ads"||d.category==="tracking") && !BLOCKED[d.domain]);
  if (DEMO){  // demo mode: simulate locally, never touch the real firewall
    if (!trackers.length){
      note("blockAllNote", "No ads/tracking destinations active right now — nothing to block.");
      btn.disabled = true; setTimeout(()=>{ btn.disabled=false; }, 2200);
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span>Blocking '+trackers.length+'…';
    setTimeout(() => {
      trackers.forEach(d => { BLOCKED[d.domain] = ["203.0.113.10"]; });
      btn.disabled = false;
      btn.textContent = "⛔ Block All Trackers";
      note("blockAllNote", "[demo] Blocked "+trackers.length+" tracker domains — firewall rules simulated.");
      renderDomains(LAST_STATS.top_domains);
    }, 800);
    return;
  }
  if (!trackers.length){
    note("blockAllNote", "No ads/tracking destinations active right now — nothing to block.");
    btn.disabled = true; setTimeout(()=>{ btn.disabled=false; }, 2200);
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span class="spin"></span>Blocking '+trackers.length+'…';
  let done = 0, failed = 0;
  Promise.all(trackers.map(d =>
    fetch("/api/block-domain", {method:"POST", headers:{"Content-Type":"application/json"},
                                body:JSON.stringify({domain:d.domain})})
      .then(r => r.json())
      .then(j => { if (j.ok){ BLOCKED[d.domain]=j.ips||[]; done++; } else failed++; })
      .catch(() => failed++)
  )).then(() => {
    btn.disabled = false;
    btn.textContent = "⛔ Block All Trackers";
    note("blockAllNote", "Blocked "+done+" tracker domain"+(done===1?"":"s")+(failed?(" · "+failed+" failed"):"")+" — firewall rules active.");
    refreshStats();
  });
}
function note(id, txt){ const n = $(id); n.textContent = txt; }

/* ══════════════ bandwidth area chart ══════════════ */
const bwState = {sent:[], recv:[], yMax:1};
function niceCeil(v){
  const p = Math.pow(10, Math.floor(Math.log10(v||1)));
  const m = v/p;
  return (m<=1?1:m<=2?2:m<=2.5?2.5:m<=5?5:10)*p;
}
function smoothPath(pts){
  if (pts.length < 2) return "";
  let d = "M "+pts[0][0].toFixed(1)+" "+pts[0][1].toFixed(1);
  for (let i=0; i<pts.length-1; i++){
    const p0 = pts[Math.max(0,i-1)], p1 = pts[i], p2 = pts[i+1], p3 = pts[Math.min(pts.length-1,i+2)];
    const c1x = p1[0]+(p2[0]-p0[0])/6, c1y = p1[1]+(p2[1]-p0[1])/6;
    const c2x = p2[0]-(p3[0]-p1[0])/6, c2y = p2[1]-(p3[1]-p1[1])/6;
    d += " C "+c1x.toFixed(1)+" "+c1y.toFixed(1)+" "+c2x.toFixed(1)+" "+c2y.toFixed(1)+" "+p2[0].toFixed(1)+" "+p2[1].toFixed(1);
  }
  return d;
}
function drawBw(sent, recv, yMax){
  const W=340, H=130, PL=6, PR=6, PT=10, PB=16;
  const n = Math.max(sent.length, recv.length, 2);
  const iw = W-PL-PR, ih = H-PT-PB;
  const px = i => PL + iw*i/(n-1);
  const py = v => PT + ih*(1 - v/yMax);
  const toPts = arr => { const p=[]; for(let i=0;i<n;i++) p.push([px(i), py(arr[i]||0)]); return p; };
  const sPts = toPts(sent), rPts = toPts(recv);
  const sLine = smoothPath(sPts), rLine = smoothPath(rPts);
  const area = (pts,line) => line+" L "+pts[pts.length-1][0].toFixed(1)+" "+(H-PB)+" L "+pts[0][0].toFixed(1)+" "+(H-PB)+" Z";
  let grid = "";
  for (let g=1; g<=3; g++){
    const y = PT + ih*g/4;
    grid += '<line x1="'+PL+'" y1="'+y+'" x2="'+(W-PR)+'" y2="'+y+'" stroke="rgba(148,180,255,.07)" stroke-width="1"/>';
  }
  $("bwChart").innerHTML =
    '<defs>'
    + '<linearGradient id="gUp" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff4d5e" stop-opacity=".32"/><stop offset="1" stop-color="#ff4d5e" stop-opacity="0"/></linearGradient>'
    + '<linearGradient id="gDn" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#3fa9f5" stop-opacity=".32"/><stop offset="1" stop-color="#3fa9f5" stop-opacity="0"/></linearGradient>'
    + '</defs>'
    + grid
    + '<path d="'+area(sPts,sLine)+'" fill="url(#gUp)"/>'
    + '<path d="'+area(rPts,rLine)+'" fill="url(#gDn)"/>'
    + '<path d="'+sLine+'" fill="none" stroke="#ff4d5e" stroke-width="1.8" stroke-linecap="round"/>'
    + '<path d="'+rLine+'" fill="none" stroke="#3fa9f5" stroke-width="1.8" stroke-linecap="round"/>'
    + '<circle cx="'+sPts[sPts.length-1][0]+'" cy="'+sPts[sPts.length-1][1]+'" r="2.6" fill="#ff4d5e"/>'
    + '<circle cx="'+rPts[rPts.length-1][0]+'" cy="'+rPts[rPts.length-1][1]+'" r="2.6" fill="#3fa9f5"/>';
}
function renderBandwidth(series){
  const rows = (series||[]).slice(-30);
  const sent = rows.map(r => r.bytes_sent||0);
  const recv = rows.map(r => r.bytes_recv||0);
  const peak = Math.max(1, ...sent, ...recv);
  const yMaxT = niceCeil(peak*1.18);
  const f = bwState;
  const pad = (a,n) => { const r=a.slice(); while(r.length<n) r.push(r.length?r[r.length-1]:0); return r; };
  const n = Math.max(sent.length, f.sent.length);
  const s0=pad(f.sent,n), s1=pad(sent,n), r0=pad(f.recv,n), r1=pad(recv,n), y0=f.yMax, y1=yMaxT;
  tween("bw", e => {
    const si = s0.map((v,i)=>v+(s1[i]-v)*e), ri = r0.map((v,i)=>v+(r1[i]-v)*e), ym = y0+(y1-y0)*e;
    drawBw(si, ri, ym);
  }, 700);
  bwState.sent = sent; bwState.recv = recv; bwState.yMax = yMaxT;
  $("bwScale").textContent = "per minute · peak "+fmtBytes(yMaxT);
}

/* ══════════════ donut ══════════════ */
const donutState = {fracs:{}};
function polar(cx,cy,r,a){ return [cx+r*Math.cos(a), cy+r*Math.sin(a)]; }
function donutSeg(cx,cy,r0,r1,a0,a1){
  const large = (a1-a0) > Math.PI ? 1 : 0;
  const [x0,y0]=polar(cx,cy,r1,a0), [x1,y1]=polar(cx,cy,r1,a1);
  const [x2,y2]=polar(cx,cy,r0,a1), [x3,y3]=polar(cx,cy,r0,a0);
  return "M "+x0.toFixed(2)+" "+y0.toFixed(2)+" A "+r1+" "+r1+" 0 "+large+" 1 "+x1.toFixed(2)+" "+y1.toFixed(2)
       + " L "+x2.toFixed(2)+" "+y2.toFixed(2)+" A "+r0+" "+r0+" 0 "+large+" 0 "+x3.toFixed(2)+" "+y3.toFixed(2)+" Z";
}
function renderDonut(byCat){
  const entries = Object.entries(byCat||{}).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]);
  const total = entries.reduce((s,[,v])=>s+v,0);
  const top = entries.slice(0,5);
  const other = entries.slice(5).reduce((s,[,v])=>s+v,0);
  if (other>0) top.push(["other", other]);
  const fracsT = {};
  top.forEach(([k,v]) => fracsT[k] = total? v/total : 0);
  const f0 = donutState.fracs, keys = [...new Set([...Object.keys(f0), ...Object.keys(fracsT)])];
  tween("donut", e => {
    let a = -Math.PI/2, paths = "";
    const gap = 0.02;
    keys.forEach(k => {
      const from = f0[k]||0, to = fracsT[k]||0;
      const fr = from+(to-from)*e;
      if (fr <= 0.001) return;
      const a1 = a + fr*Math.PI*2;
      const col = k==="other" ? "#3b4a5e" : catColor(k);
      paths += '<path d="'+donutSeg(70,70,42,60,a+gap/2,a1-gap/2)+'" fill="'+col+'" opacity=".92"/>';
      a = a1;
    });
    $("donut").innerHTML = paths
      + '<text x="70" y="66" text-anchor="middle" fill="#dbe7f4" font-size="13" font-weight="700" font-family="ui-monospace,monospace">'+esc(fmtBytes(total*e))+'</text>'
      + '<text x="70" y="82" text-anchor="middle" fill="#7a8aa0" font-size="8" letter-spacing="1.5">24H SENT</text>';
  }, 700);
  donutState.fracs = fracsT;
  $("donutLegend").innerHTML = top.map(([k,v]) => {
    const col = k==="other" ? "#3b4a5e" : catColor(k);
    const pct = total? Math.round(v/total*100) : 0;
    return '<span class="li"><span class="chip" style="background:'+col+'"></span>'+esc(k)+'<b>'+pct+'%</b></span>';
  }).join("") || '<span class="dim">no data yet</span>';
}

/* ══════════════ top receivers ══════════════ */
function renderReceivers(byCompany){
  const entries = Object.entries(byCompany||{}).filter(([,v])=>v>0)
    .sort((a,b)=>b[1]-a[1]).slice(0,6);
  const el = $("receivers");
  if (!entries.length){ el.innerHTML = '<div class="empty">—</div>'; return; }
  const max = entries[0][1];
  el.innerHTML = entries.map(([k,v]) =>
    '<div class="recv-row"><div class="recv-top"><span class="recv-name">'+esc(k)+'</span>'
    + '<span class="recv-bytes">'+fmtBytes(v)+'</span></div>'
    + '<div class="recv-bar"><div class="recv-fill" data-w="'+(Math.max(2,v/max*100)).toFixed(1)+'"></div></div></div>'
  ).join("");
  requestAnimationFrame(() => requestAnimationFrame(() =>
    el.querySelectorAll(".recv-fill").forEach(f => { f.style.width = f.getAttribute("data-w")+"%"; })));
}

/* ══════════════ verdicts feed ══════════════ */
const cards = new Map();
function cardEl(it){
  const risk = (it.risk||"?").toUpperCase();
  const cls = risk==="RED"?"risk-red":risk==="YELLOW"?"risk-yellow":"risk-green";
  const card = document.createElement("div");
  card.className = "vcard "+cls;
  card.dataset.id = it.id;
  card.innerHTML =
    '<div class="vhead">'
    + '<span class="vdot"></span><span class="vrisk">'+esc(risk)+'</span>'
    + '<span class="vproc mono">'+esc(it.process_name||"unknown")
    +   ' <button class="qb" data-q="What is '+esc(it.process_name||"unknown")+' and why is it using data?">?</button></span>'
    + '<span class="vtime mono">'+new Date(it.ts*1000).toLocaleTimeString()+'</span>'
    + '</div>'
    + '<div class="vbody">'
    + '<div class="valert">'+esc(it.alert_name||"alert")+'</div>'
    + '<div class="vexpl">'+esc(it.explanation||"")+'</div>'
    + (it.risk_reason ? '<div class="vreason">⚠ '+esc(it.risk_reason)+'</div>' : "")
    + '<div class="voutcome-slot"></div>'
    + '<div class="vactions"></div>'
    + '</div>'
    + '<div class="vfixed-line">✓ FIXED — '+esc(it.process_name||"")+' · '+new Date(it.ts*1000).toLocaleTimeString()+'</div>';
  return card;
}
function renderCardState(card, it){
  const actions = card.querySelector(".vactions");
  const oc = card.querySelector(".voutcome-slot");
  if (it.fix_status === "fixed" || it.fix_status === "failed"){
    const ok = it.fix_status === "fixed";
    oc.innerHTML = it.outcome ? '<div class="voutcome'+(ok?"":" err")+'">'+esc(it.outcome)+'</div>' : "";
    actions.innerHTML = '<button class="btn fix '+(ok?"done":"bad")+'" disabled>'
      + (ok?"FIXED ✓":"FIX FAILED — RETRY")+'</button>';
    if (!ok){
      const b = actions.querySelector("button");
      b.disabled = false;
      b.addEventListener("click", () => fixIt(it.id, card, it));
    }
    if (ok && !card.classList.contains("fixed")){
      card.classList.add("fixed","flash");
      setTimeout(() => card.classList.add("collapsed"), 1600);
    }
    if (!ok) card.classList.remove("collapsed");
    return;
  }
  if (card.dataset.fixing === "1"){
    actions.innerHTML = '<button class="btn fix" disabled><span class="spin"></span>Fixing…</button>';
    return;
  }
  actions.innerHTML = '<button class="btn fix">Fix It ('+esc(it.action||"ignore")+')</button>';
  actions.querySelector("button").addEventListener("click", () => fixIt(it.id, card, it));
}
function fixIt(id, card, it){
  card.dataset.fixing = "1";
  const b = card.querySelector(".vactions button");
  if (b){ b.disabled = true; b.innerHTML = '<span class="spin"></span>Fixing…'; }
  const payload = DEMO && it
    ? {id, demo:true, action:it.action, process_name:it.process_name, action_params:it.action_params||{}}
    : {id};
  fetch("/execute", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(payload)})
    .then(r => r.json())
    .then(d => {
      delete card.dataset.fixing;
      refreshReport();
    })
    .catch(() => {
      delete card.dataset.fixing;
      const b2 = card.querySelector(".vactions button");
      if (b2){ b2.disabled = false; b2.textContent = "Retry Fix"; }
    });
}
function renderFeed(items){
  const feed = $("feed");
  if (!items || !items.length){
    feed.innerHTML = '<div class="empty">No alerts analyzed yet — Astrid is watching.</div>';
    cards.clear();
    $("verdictCount").textContent = "";
    return;
  }
  const empty = feed.querySelector(".empty");
  if (empty) empty.remove();
  const inWindow = new Set(items.map(i => i.id));
  for (const [id, c] of cards){       // prune items that slid out of the window
    if (!inWindow.has(id)){ c.remove(); cards.delete(id); }
  }
  items.slice().reverse().forEach(it => {   // newest first in DOM
    let card = cards.get(it.id);
    if (!card){
      card = cardEl(it);
      cards.set(it.id, card);
      renderCardState(card, it);
      feed.prepend(card);
      card.classList.add("enter");
    } else {
      renderCardState(card, it);
    }
  });
  // keep DOM ordered newest-first (server sends chronological)
  items.slice().reverse().forEach(it => {
    const c = cards.get(it.id);
    if (c && feed.firstChild !== c) feed.prepend(c);
  });
  $("verdictCount").textContent = "· " + items.length + " recent";
}

/* ══════════════ chat ══════════════ */
function addMsg(who, text){
  const log = $("chatLog");
  const div = document.createElement("div");
  div.className = "msg "+who;
  div.innerHTML = '<span class="who">'+(who==="you"?"you":"astrid")+' ›</span>';
  div.appendChild(document.createTextNode(text));
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}
function sendChat(text){
  const inp = $("chatIn");
  const q = (text != null ? text : inp.value).trim();
  if (!q) return;
  inp.value = "";
  addMsg("you", q);
  const t = addMsg("astrid", "");
  t.innerHTML = '<span class="who">astrid ›</span><span class="typing"><i></i><i></i><i></i></span>';
  fetch("/chat", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({question:q})})
    .then(r => r.json())
    .then(d => { t.remove(); addMsg("astrid", d.answer || JSON.stringify(d)); })
    .catch(() => { t.remove(); addMsg("astrid", "(couldn't reach the analyst — is the service up?)"); });
}
function askAbout(question){
  sendChat(question);
  document.querySelector(".chat-panel").scrollIntoView({behavior:"smooth", block:"nearest"});
}

/* ══════════════ header live rate ══════════════ */
function updateHeader(stats){
  const rows = stats.bandwidth_series || [];
  const last = rows[rows.length-1];
  let upBps = 0, dnBps = 0;
  if (last){
    const age = Math.max(8, Math.min(60, (stats.ts||0) - last.ts));
    upBps = (last.bytes_sent||0)/age;
    dnBps = (last.bytes_recv||0)/age;
  }
  $("bwUp").textContent = fmtRate(upBps);
  $("bwDown").textContent = fmtRate(dnBps);
}

/* ══════════════ polling ══════════════ */
let LAST_STATS = {};
let netFail = 0;
function markNet(ok){
  netFail = ok ? 0 : netFail+1;
  $("liveDot").classList.toggle("warn", netFail >= 2);
}
function refreshStats(){
  return fetch("/api/stats"+demoQS())
    .then(r => r.json())
    .then(s => {
      markNet(true);
      LAST_STATS = s;
      BLOCKED = s.blocked || BLOCKED;
      updateHeader(s);
      renderMap(s.top_domains);
      renderDomains(s.top_domains);
      renderBandwidth(s.bandwidth_series);
      renderDonut(s.by_category);
      renderReceivers(s.by_company);
      const t = s.totals || {};
      countUp("stBytes", t.bytes_24h||0, fmtBytes);
      countUp("stProcs", t.processes_seen||0, v=>String(v));
      countUp("stThreats", t.threats||0, v=>String(v));
      countUp("stFixed", t.fixed||0, v=>String(v));
    })
    .catch(() => markNet(false));
}
function refreshReport(){
  return fetch("/report"+demoQS())
    .then(r => r.json())
    .then(d => { markNet(true); renderFeed(d.items||[]); })
    .catch(() => markNet(false));
}
function refreshAll(){ refreshStats(); refreshReport(); }

/* ══════════════ boot ══════════════ */
document.addEventListener("click", e => {
  const qb = e.target.closest(".qb");
  if (qb && qb.dataset.q){ askAbout(qb.dataset.q); }
});
$("chatSend").addEventListener("click", () => sendChat());
$("chatIn").addEventListener("keydown", e => { if (e.key === "Enter") sendChat(); });
$("blockAllBtn").addEventListener("click", blockAllTrackers);
$("viewAstridBtn").addEventListener("click", () => setView("astrid"));
$("viewSignozBtn").addEventListener("click", () => setView("signoz"));
$("demoCheck").addEventListener("change", e => setDemo(e.target.checked));
applyView();
applyDemo();
drawMapDots();
renderMap([]);
refreshAll();
setInterval(refreshAll, POLL);
</script>
</body>
</html>
"""
# __CONSOLE_HTML_END__


@app.get("/", response_class=HTMLResponse)
def console():
    """Browser console: single embedded page, no CDNs, mobile-friendly."""
    return CONSOLE_HTML

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
