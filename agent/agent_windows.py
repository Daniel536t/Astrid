#!/usr/bin/env python3
"""
Astrid Windows capture agent — per-process network byte attribution.

Mirrors agent_linux.py's design, swapping the sensor layer:
  - CONNECTIONS: psutil.net_connections(kind="tcp") gives the 4-tuple ->
    owning PID map (run as Administrator to see every user's connections).
  - BYTES: iphlpapi GetPerTcpConnectionEStats(TCP_ESTATS_DATA_ROD) — the same
    per-connection cumulative byte counters the Linux agent reads from
    ss/tcp_info. Diffed every scan into per-PID deltas. If a connection's
    counters read as unavailable, we try SetPerTcpConnectionEStats once to
    enable DATA collection, then keep going (some builds gate it).
  - DESTINATIONS: reverse DNS per remote IP (cached), same domain -> category/
    company maps as the Linux agent (kept self-contained so the installer
    ships ONE file — update both agents together).
  - IPv6 connections are enumerated but not byte-counted yet (needs the
    GetPerTcp6ConnectionEStats row layout) — v4 carries the demo story.

Exports OTLP/HTTP metrics (net.bytes_sent / net.bytes_recv cumulative per
process, attr: process_name, remote_domain, category, company, host) to
OTLP_ENDPOINT — normally the console's /otlp proxy, e.g.
http://13.217.12.249:9000/otlp — so no collector port is needed.

Requires: Windows Vista+, Python 3.9+, `pip install psutil opentelemetry-sdk
opentelemetry-exporter-otlp-proto-http`, Administrator shell.
The /agent.ps1 installer on the console does all of this.
"""

import os
import socket
import struct
import sys
import time
import ctypes
from ctypes import wintypes

import psutil
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

OTLP_ENDPOINT = os.getenv("OTLP_ENDPOINT", "http://localhost:4318")
HOST_NAME = os.getenv("ASTRID_HOST_NAME") or socket.gethostname()
FLUSH_SECONDS = 5
SCAN_SECONDS = 5

# ────────────────────── DOMAIN CLASSIFICATION ──────────────────────
# Keep in sync with agent_linux.py (both files are deployed standalone).
DOMAIN_CATEGORIES = {
    "ads": ["doubleclick.net", "googlesyndication.com", "adservice.google.com",
            "amazon-adsystem.com", "ads.yahoo.com", "advertising.com"],
    "tracking": ["google-analytics.com", "googletagmanager.com", "segment.io",
                 "segment.com", "mixpanel.com", "hotjar.com", "fullstory.com",
                 "telemetry.mozilla.org", "app-measurement.com"],
    "cdn": ["cloudfront.net", "akamaized.net", "akamai.net", "fastly.net",
            "cloudflare.com", "cdn77.org", "edgecastcdn.net", "jsdelivr.net"],
    "os-updates": ["windowsupdate.com", "update.microsoft.com", "archive.ubuntu.com",
                   "security.ubuntu.com"],
    "streaming": ["netflix.com", "nflxvideo.net", "youtube.com", "googlevideo.com",
                  "spotify.com", "scdn.co", "twitch.tv", "hulu.com"],
    "local": ["localhost", "lan"],
}
DOMAIN_COMPANIES = {
    "google": "Google", "googlevideo": "Google", "gstatic": "Google",
    "1e100": "Google", "googleusercontent": "Google", "youtube": "Google",
    "microsoft": "Microsoft", "windowsupdate": "Microsoft", "azure": "Microsoft",
    "bing": "Microsoft", "live.com": "Microsoft", "github": "GitHub",
    "wikimedia": "Wikimedia", "fastly": "Fastly",
    "amazon": "Amazon", "aws": "Amazon", "cloudfront": "Amazon",
    "netflix": "Netflix", "nflxvideo": "Netflix", "spotify": "Spotify",
    "facebook": "Meta", "fbcdn": "Meta", "cloudflare": "Cloudflare",
    "akamai": "Akamai", "mozilla": "Mozilla", "apple": "Apple",
    "anthropic": "Anthropic", "nvidia": "NVIDIA", "openai": "OpenAI",
    "localhost": "this machine", "lan": "local network",
}
PRIVATE_NETS = [("10.",), ("192.168.",), ("169.254.",)] + \
               [tuple([f"172.{i}."]) for i in range(16, 32)]


def classify_domain(domain: str):
    d = domain.lower().rstrip(".")
    for cat, suffixes in DOMAIN_CATEGORIES.items():
        if any(d == s or d.endswith("." + s) for s in suffixes):
            company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
            return cat, company
    company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
    return "unknown", company


# ────────────────────── IP -> DOMAIN ──────────────────────
_dns_cache: dict = {}


def resolve_ip(ip: str) -> str:
    if ip in _dns_cache:
        return _dns_cache[ip]
    if ip.startswith(("127.", "::1")):
        domain = "localhost"
    elif any(ip.startswith(p[0]) for p in PRIVATE_NETS):
        domain = "lan"
    else:
        try:
            domain = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            domain = ip
    _dns_cache[ip] = domain
    return domain


def proc_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        return f"pid-{pid}"


# ────────────────────── IPHLPAPI ESTATS (per-connection bytes) ──────────────────────
TCP_ESTATS_DATA_ROD = 0           # TCP_ESTATS_TYPE enum value for DATA read-only
MIB_TCP_STATE_ESTAB = 5
ERROR_INVALID_PARAMETER = 87


class TCP_ESTATS_DATA_ROD_V0(ctypes.Structure):
    _fields_ = [
        ("DataBytesOut", ctypes.c_uint64),
        ("DataSegsOut", ctypes.c_uint64),
        ("DataBytesIn", ctypes.c_uint64),
        ("DataSegsIn", ctypes.c_uint64),
        ("SegsOut", ctypes.c_uint64),
        ("SegsIn", ctypes.c_uint64),
        ("SoftErrors", wintypes.ULONG),
        ("SoftErrorReason", wintypes.ULONG),
        ("SndUna", wintypes.ULONG),
        ("SndNxt", wintypes.ULONG),
        ("SndMax", wintypes.ULONG),
        ("ThruBytesAcked", ctypes.c_uint64),
        ("ThruBytesReceived", ctypes.c_uint64),
    ]


class TCP_ESTATS_DATA_RW_V0(ctypes.Structure):
    _fields_ = [("EnableCollection", wintypes.BOOLEAN)]


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.ULONG),
        ("dwLocalAddr", wintypes.ULONG),
        ("dwLocalPort", wintypes.ULONG),
        ("dwRemoteAddr", wintypes.ULONG),
        ("dwRemotePort", wintypes.ULONG),
    ]


_iphlpapi = None
_estats_available = None  # None=untested, True/False once known


def _ip_to_dw(ip: str) -> int:
    # Network-order bytes read as a little-endian DWORD — the layout
    # GetPerTcpConnectionEStats expects in MIB_TCPROW.
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _conn_bytes(local_ip: str, local_port: int,
                remote_ip: str, remote_port: int):
    """Cumulative (bytes_out, bytes_in) for one TCP connection, or None."""
    global _iphlpapi, _estats_available
    if _estats_available is False:
        return None
    try:
        if _iphlpapi is None:
            _iphlpapi = ctypes.windll.iphlpapi
        row = MIB_TCPROW()
        row.dwState = MIB_TCP_STATE_ESTAB
        row.dwLocalAddr = _ip_to_dw(local_ip)
        row.dwLocalPort = socket.htons(local_port) & 0xFFFF
        row.dwRemoteAddr = _ip_to_dw(remote_ip)
        row.dwRemotePort = socket.htons(remote_port) & 0xFFFF
        rod = TCP_ESTATS_DATA_ROD_V0()
        rc = _iphlpapi.GetPerTcpConnectionEStats(
            ctypes.byref(row), TCP_ESTATS_DATA_ROD,
            None, 0, 0, None, 0, 0,
            ctypes.byref(rod), 0, ctypes.sizeof(rod))
        if rc != 0:
            # Some builds need DATA collection explicitly enabled once.
            rw = TCP_ESTATS_DATA_RW_V0()
            rw.EnableCollection = True
            rc2 = _iphlpapi.SetPerTcpConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA_ROD,
                ctypes.byref(rw), 0, ctypes.sizeof(rw))
            if rc2 != 0:
                if rc == ERROR_INVALID_PARAMETER:
                    _estats_available = False
                return None
            rc = _iphlpapi.GetPerTcpConnectionEStats(
                ctypes.byref(row), TCP_ESTATS_DATA_ROD,
                None, 0, 0, None, 0, 0,
                ctypes.byref(rod), 0, ctypes.sizeof(rod))
            if rc != 0:
                return None
        _estats_available = True
        return rod.DataBytesOut, rod.DataBytesIn
    except Exception:
        return None


# ────────────────────── CONNECTION SNAPSHOT + DIFF ──────────────────────
_prev: dict = {}  # (lip, lport, rip, rport, pid) -> (bytes_out, bytes_in)


def snapshot() -> dict:
    """Current cumulative bytes per live TCP connection (IPv4, has remote)."""
    snap = {}
    try:
        conns = psutil.net_connections(kind="tcp")
    except Exception:
        return snap
    for c in conns:
        if not c.pid or not c.raddr or not c.laddr:
            continue
        try:
            lip, lport = c.laddr.ip, c.laddr.port
            rip, rport = c.raddr.ip, c.raddr.port
        except AttributeError:
            continue
        if ":" in lip or ":" in rip:
            continue  # v6: enumerated but not byte-counted yet
        b = _conn_bytes(lip, lport, rip, rport)
        if b is not None:
            snap[(lip, lport, rip, rport, c.pid)] = b
    return snap


def deltas() -> dict:
    """Per-(pid, domain) (sent_delta, recv_delta) since the last call. First
    sighting of a connection only records a baseline — same rule as the Linux
    agent, so a long-lived connection's history is never dumped in as one
    giant spike. Attribution is EXACT here: every connection has precisely
    one remote IP, so chrome.exe→googlevideo.com flows come out real."""
    global _prev
    cur = snapshot()
    per_pair: dict = {}
    for key, (tx, rx) in cur.items():
        pid, rip = key[4], key[2]
        old = _prev.get(key)
        if old is not None:
            dtx, drx = tx - old[0], rx - old[1]
            if dtx > 0 or drx > 0:
                pair = per_pair.setdefault((pid, resolve_ip(rip)), [0, 0])
                pair[0] += max(dtx, 0)
                pair[1] += max(drx, 0)
    _prev = cur
    return per_pair


# ────────────────────── OTEL SETUP ──────────────────────
def make_exporter():
    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
        OTLPMetricExporter,
    )
    ep = OTLP_ENDPOINT.rstrip("/")
    if not ep.endswith("/v1/metrics"):
        ep += "/v1/metrics"  # explicit endpoint= is used verbatim by the SDK
    return OTLPMetricExporter(endpoint=ep)


resource = Resource.create({"service.name": "astrid-agent",
                            "host.name": HOST_NAME})
reader = PeriodicExportingMetricReader(make_exporter(),
                                       export_interval_millis=FLUSH_SECONDS * 1000)
provider = MeterProvider(resource=resource, metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter("astrid-agent")
c_sent = meter.create_counter("net.bytes_sent", unit="By",
                              description="Bytes sent per process")
c_recv = meter.create_counter("net.bytes_recv", unit="By",
                              description="Bytes received per process")

def emit(pid: int, domain: str, sent_bytes: float, recv_bytes: float):
    if sent_bytes <= 0 and recv_bytes <= 0:
        return
    name = proc_name(pid)
    category, company = classify_domain(domain)
    attrs = {"process_name": name, "remote_domain": domain,
             "category": category, "company": company,
             "host": HOST_NAME}
    if sent_bytes > 0:
        c_sent.add(int(sent_bytes), attrs)
    if recv_bytes > 0:
        c_recv.add(int(recv_bytes), attrs)


def main():
    if sys.platform != "win32":
        print("[agent] agent_windows.py must run on Windows", flush=True)
        sys.exit(1)
    print(f"[agent] starting as host '{HOST_NAME}'; OTLP -> {OTLP_ENDPOINT}, "
          f"scan {SCAN_SECONDS}s / flush {FLUSH_SECONDS}s", flush=True)
    deltas()  # baseline: existing connections start counting from NOW
    while True:
        time.sleep(SCAN_SECONDS)
        try:
            for (pid, domain), (dtx, drx) in deltas().items():
                emit(pid, domain, dtx, drx)
        except Exception as e:
            print(f"[agent] scan error (continuing): {e}", flush=True)


if __name__ == "__main__":
    main()
