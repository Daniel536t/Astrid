#!/usr/bin/env python3
"""
Astrid demo vampire — simulates a bandwidth-draining process.
POSTs random bytes to the local sink at a configurable rate, disguised with
the innocuous process title "svc-updater". Loopback only: the demo is
hermetic, nothing leaves the box.

  python3 vampire.py --mbps 5 --target http://127.0.0.1:9999/
"""

import argparse
import http.client
import os
import time
from urllib.parse import urlparse

import setproctitle

CHUNK = 256 * 1024  # POST size per request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mbps", type=float, default=5.0,
                    help="megabytes per second to upload (default 5)")
    ap.add_argument("--target", default="http://127.0.0.1:9999/")
    args = ap.parse_args()

    setproctitle.setproctitle("svc-updater")

    url = urlparse(args.target)
    port = url.port or (443 if url.scheme == "https" else 80)
    path = url.path or "/"
    rate = args.mbps * 1_000_000  # bytes/sec
    buf = os.urandom(1024 * 1024)  # 1MB random pool, cycled
    off = 0
    sent_total = 0
    started = time.time()

    print(f"[vampire] draining {args.mbps} MB/s -> {args.target} as 'svc-updater'",
          flush=True)
    while True:
        try:
            conn = http.client.HTTPConnection(url.hostname, port, timeout=10)
            while True:
                if off + CHUNK > len(buf):
                    off = 0
                body = memoryview(buf)[off:off + CHUNK]
                off += CHUNK
                t0 = time.monotonic()
                conn.request("POST", path, body=body,
                             headers={"Content-Type": "application/octet-stream"})
                resp = conn.getresponse()
                resp.read()
                sent_total += CHUNK
                # token-bucket pacing: next send not before chunk/rate elapsed
                t0 += CHUNK / rate
                delay = t0 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
        except (OSError, http.client.HTTPException) as e:
            print(f"[vampire] connection error ({e}); retrying in 2s", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
