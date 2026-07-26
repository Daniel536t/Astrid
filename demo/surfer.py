#!/usr/bin/env python3
"""Astrid demo web-surfer — REAL external browsing traffic, honestly labeled.

Fetches real sites over HTTPS in a slow, gentle loop so the LIVE console
paints recognizable brands with real DNS, real TLS, real bytes and real geo
arcs — the "me visiting YouTube" experience on a headless server. The process
name is deliberately honest: it IS a simulated user, and Top Processes / chat
will say exactly that if asked. Gentle by design: one page per ~7-18s, a few
MB per hour. Run for demos: sudo systemctl start astrid-surfer
"""
import random
import time

import httpx
import setproctitle

SITES = [
    "https://www.youtube.com/",
    "https://www.google.com/",
    "https://github.com/",
    "https://www.wikipedia.org/",
    "https://www.netflix.com/",
    "https://aws.amazon.com/",
    "https://ubuntu.com/",
    "https://open.spotify.com/",
]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def main() -> None:
    setproctitle.setproctitle("web-surfer")
    print("[surfer] starting — real fetches, gentle pace", flush=True)
    with httpx.Client(follow_redirects=True, timeout=12,
                      headers={"User-Agent": UA}) as c:
        while True:
            url = random.choice(SITES)
            try:
                r = c.get(url)
                print(f"[surfer] {url} -> {r.status_code}, "
                      f"{len(r.content)} bytes", flush=True)
            except Exception as e:
                print(f"[surfer] {url} failed: {e}", flush=True)
            time.sleep(random.uniform(7, 18))


if __name__ == "__main__":
    main()
