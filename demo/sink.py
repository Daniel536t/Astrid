#!/usr/bin/env python3
"""
Astrid demo sink — local HTTP server that accepts POST bodies and discards
them. Loopback only (127.0.0.1:9999): the demo is hermetic, nothing leaves
the box (AWS egress costs money).
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import setproctitle

BIND = ("127.0.0.1", 9999)


class Sink(BaseHTTPRequestHandler):
    # HTTP/1.1 keep-alive: connections must be long-lived so the capture
    # agent's per-connection byte accounting (ss tcp_info) can attribute
    # loopback traffic to the right pid. With HTTP/1.0 each POST is a
    # sub-millisecond connection that snapshots always miss.
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        remaining = int(self.headers.get("Content-Length", 0))
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 1 << 16))
            if not chunk:
                break
            remaining -= len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        body = b'{"status":"sink up"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    setproctitle.setproctitle("astrid-sink")
    print(f"[sink] discarding POSTs on http://{BIND[0]}:{BIND[1]}", flush=True)
    ThreadingHTTPServer(BIND, Sink).serve_forever()
