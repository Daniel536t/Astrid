#!/usr/bin/env python3
"""
Astrid Linux capture agent — per-process network byte attribution.

Hybrid capture (verified against this box, 2026-07-24):
  - PRIMARY: nethogs trace mode (`nethogs -t`, real interfaces only) for
    per-process byte rates. Format: blocks starting with "Refreshing:", then
    "<cmd>/<pid>/<uid>\t<sent_KBps>\t<recv_KBps>" (cmd may contain '/').
  - LOOPBACK: owned by `ss -tinpH` tcp_info sampling (bytes_sent /
    bytes_received per connection), diffed every nethogs tick into per-pid
    deltas — EXACT loopback attribution. nethogs is kept off loopback
    deliberately: it shows short-lived lo connections as "unknown TCP/0/0"
    and double-counts persistent ones (verified on this box).
  - DESTINATIONS: neither source gives domains; psutil.net_connections maps
    pid -> remote IPs -> reverse DNS -> category/company classification.

Exports OTLP metrics to localhost:4317 (insecure), service.name=astrid-agent:
  net.bytes_sent, net.bytes_recv (cumulative counters, unit By),
  net.new_domain_seen (counter, +1 when a pid first resolves a new domain).
Attributes: process_name, remote_domain, category, company.
"""

import ipaddress
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict

import psutil
from opentelemetry import metrics
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource

OTLP_ENDPOINT = os.getenv("OTLP_ENDPOINT", "http://localhost:4317")
FLUSH_SECONDS = 5
# No -a: monitor real interfaces only. Loopback is owned by the ss path below —
# with -a, nethogs ALSO attributes persistent loopback connections and every
# byte would be counted twice (verified: svc-updater appeared on both paths).
NETHOGS_CMD = ["nethogs", "-t"]

# ────────────────────── DOMAIN CLASSIFICATION ──────────────────────
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
    "1e100": "Google", "googleusercontent": "Google", "youtube": "Google",
    "microsoft": "Microsoft", "windowsupdate": "Microsoft", "azure": "Microsoft",
    "github": "GitHub", "wikimedia": "Wikimedia", "fastly": "Fastly",
    "ubuntu": "Canonical", "amazon": "Amazon", "aws": "Amazon", "cloudfront": "Amazon",
    "netflix": "Netflix", "nflxvideo": "Netflix", "spotify": "Spotify",
    "facebook": "Meta", "fbcdn": "Meta", "cloudflare": "Cloudflare",
    "akamai": "Akamai", "mozilla": "Mozilla", "apple": "Apple",
    "anthropic": "Anthropic", "nvidia": "NVIDIA", "openai": "OpenAI",
    "localhost": "this machine", "lan": "local network",
}
PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]


def classify_domain(domain: str) -> tuple[str, str]:
    """Return (category, company) for a domain."""
    d = domain.lower().rstrip(".")
    for cat, suffixes in DOMAIN_CATEGORIES.items():
        if any(d == s or d.endswith("." + s) for s in suffixes):
            company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
            return cat, company
    company = next((c for k, c in DOMAIN_COMPANIES.items() if k in d), "unknown")
    return "unknown", company


# ────────────────────── PID -> DOMAIN RESOLUTION ──────────────────────
_dns_cache: dict[str, str] = {}
_dns_lock = threading.Lock()


def resolve_ip(ip: str) -> str:
    """IP -> domain. Loopback/RFC1918 short-circuit; PTR for public, cached."""
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback:
            domain = "localhost"
        elif any(addr in n for n in PRIVATE_NETS):
            domain = "lan"
        else:
            domain = socket.gethostbyaddr(ip)[0]
    except (ipaddress.AddressValueError, socket.herror, socket.gaierror, OSError):
        domain = ip
    with _dns_lock:
        _dns_cache[ip] = domain
    return domain


class ConnMap:
    """pid -> set of remote domains, refreshed periodically via psutil."""

    def __init__(self):
        self._map: dict[int, set[str]] = {}
        self._ts = 0.0

    def refresh(self, force: bool = False):
        if not force and time.time() - self._ts < 5:
            return
        m: dict[int, set[str]] = defaultdict(set)
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.pid and c.raddr and c.raddr.ip:
                    m[c.pid].add(resolve_ip(c.raddr.ip))
        except (psutil.Error, PermissionError):
            pass
        self._map = m
        self._ts = time.time()

    def domains_for(self, pid: int) -> set[str]:
        self.refresh()
        return self._map.get(pid) or {"unknown"}


def proc_name(pid: int, nethogs_label: str = "") -> str:
    """Canonical process name: psutil (respects setproctitle) first."""
    try:
        return psutil.Process(pid).name()
    except psutil.Error:
        pass
    label = nethogs_label.split(":")[0]
    return os.path.basename(label) if label.startswith("/") else (label or f"pid-{pid}")


# ────────────────────── LOOPBACK EXACT ACCOUNTING (ss tcp_info) ──────────────────────
_PID_RE = re.compile(r"pid=(\d+)")
_SENT_RE = re.compile(r"bytes_sent:(\d+)")
_RECV_RE = re.compile(r"bytes_received:(\d+)")


def _is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr.startswith("[::1]")


def ss_loopback_snapshot() -> dict[tuple, tuple[int, int, int]]:
    """Per-loopback-connection cumulative bytes from ss tcp_info.

    Returns {(local, peer, pid): (pid, tx_bytes, rx_bytes)}. Verified format:
      ESTAB 0 0 127.0.0.1:54398 127.0.0.1:9999 users:(("svc-updater",pid=1,fd=3))
      <tab>cubic ... bytes_sent:14425180 bytes_acked:... bytes_received:6215 ...
    """
    try:
        out = subprocess.run(["ss", "-tinpH"], capture_output=True, text=True,
                             timeout=5).stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return {}
    snap: dict[tuple, tuple[int, int, int]] = {}
    pending_key = None
    for line in out.splitlines():
        if line.startswith((" ", "\t")):  # tcp_info continuation line
            if pending_key:
                tx = _SENT_RE.search(line)
                rx = _RECV_RE.search(line)
                if tx or rx:
                    local, peer, pid = pending_key
                    snap[pending_key] = (pid,
                                         int(tx.group(1)) if tx else 0,
                                         int(rx.group(1)) if rx else 0)
                pending_key = None
            continue
        fields = line.split()
        if len(fields) < 6:
            pending_key = None
            continue
        local, peer = fields[3], fields[4]
        m = _PID_RE.search(line)
        if m and (_is_loopback(local) or _is_loopback(peer)):
            pending_key = (local, peer, int(m.group(1)))
        else:
            pending_key = None
    return snap


class LoopbackTracker:
    """Diffs ss snapshots into per-pid byte deltas."""

    def __init__(self):
        self._prev: dict[tuple, tuple[int, int, int]] = {}

    def deltas(self) -> dict[int, tuple[int, int]]:
        """Returns {pid: (tx_delta, rx_delta)} since last call."""
        cur = ss_loopback_snapshot()
        per_pid: dict[int, list[int]] = defaultdict(lambda: [0, 0])
        for key, (pid, tx, rx) in cur.items():
            prev = self._prev.get(key)
            if prev is None:
                continue  # baseline: don't dump a connection's pre-existing total
            dtx, drx = tx - prev[1], rx - prev[2]
            if dtx > 0:
                per_pid[pid][0] += dtx
            if drx > 0:
                per_pid[pid][1] += drx
        self._prev = cur
        return {pid: (v[0], v[1]) for pid, v in per_pid.items()}


# ────────────────────── OTEL SETUP ──────────────────────
resource = Resource.create({"service.name": "astrid-agent"})
reader = PeriodicExportingMetricReader(
    OTLPMetricExporter(endpoint=OTLP_ENDPOINT, insecure=True),
    export_interval_millis=FLUSH_SECONDS * 1000,
)
provider = MeterProvider(resource=resource, metric_readers=[reader])
metrics.set_meter_provider(provider)
meter = metrics.get_meter("astrid-agent")
c_sent = meter.create_counter("net.bytes_sent", unit="By",
                              description="Bytes sent per process")
c_recv = meter.create_counter("net.bytes_recv", unit="By",
                              description="Bytes received per process")
c_domain = meter.create_counter("net.new_domain_seen", unit="{domain}",
                                description="New destination domain first seen")

conn_map = ConnMap()
lo_tracker = LoopbackTracker()
seen_domains: set[str] = set()  # (process, domain) pairs already announced


def emit(pid: int, label: str, sent_bytes: float, recv_bytes: float):
    if sent_bytes <= 0 and recv_bytes <= 0:
        return
    name = proc_name(pid, label)
    for domain in conn_map.domains_for(pid):
        category, company = classify_domain(domain)
        attrs = {"process_name": name, "remote_domain": domain,
                 "category": category, "company": company}
        if sent_bytes > 0:
            c_sent.add(int(sent_bytes), attrs)
        if recv_bytes > 0:
            c_recv.add(int(recv_bytes), attrs)
        if (name, domain) not in seen_domains:
            seen_domains.add((name, domain))
            c_domain.add(1, attrs)


# ────────────────────── NETHOGS PARSER + MAIN LOOP ──────────────────────
def main():
    print(f"[agent] starting; OTLP -> {OTLP_ENDPOINT}, flush {FLUSH_SECONDS}s",
          flush=True)
    while True:  # nethogs supervisor loop
        try:
            proc = subprocess.Popen(NETHOGS_CMD, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except FileNotFoundError:
            print("[agent] FATAL: nethogs not installed", flush=True)
            sys.exit(1)
        block: dict[int, tuple[str, float, float]] = {}
        for line in proc.stdout:
            line = line.rstrip("\n")
            if line.startswith("Refreshing:"):
                # End of one ~1s block: emit nethogs-attributed traffic...
                for pid, (label, s_kbps, r_kbps) in block.items():
                    emit(pid, label, s_kbps * 1024, r_kbps * 1024)
                block.clear()
                # ...then exact loopback deltas nethogs can't attribute.
                for pid, (dtx, drx) in lo_tracker.deltas().items():
                    emit(pid, "", dtx, drx)
                continue
            if "\t" not in line:
                continue
            fields = line.split("\t")
            if len(fields) < 3:
                continue
            try:
                cmd, pid_s, _uid = fields[0].rsplit("/", 2)
                pid = int(pid_s)
                if pid <= 0:
                    continue  # "unknown TCP/0/0" — loopback handled via ss
                block[pid] = (cmd, float(fields[1]), float(fields[2]))
            except (ValueError, IndexError):
                continue
        rc = proc.wait()
        print(f"[agent] nethogs exited rc={rc}; restarting in 3s", flush=True)
        time.sleep(3)


if __name__ == "__main__":
    main()
