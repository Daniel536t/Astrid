#!/usr/bin/env bash
# Astrid health watchdog — keeps the judge-facing endpoints alive.
# Runs every minute via astrid-watchdog.timer (systemd).
#
# What it covers that Restart=alone does not:
#   - analyst process alive but wedged (event-loop stall): 2 consecutive
#     failed health checks -> restart. Two-in-a-row is deliberate: a single
#     slow check can just be a /chat round-trip hogging the loop (~40-120s),
#     and restarting mid-chat would be worse than the stall.
#   - agent quietly failed: console loads but telemetry goes stale.
#   - SigNoz stack down: idempotent `docker compose up -d`.
set -u

LOG=/home/ubuntu/astrid/journal/watchdog.log
FAILS=/var/tmp/astrid-watchdog.fails
COMPOSE_DIR=/home/ubuntu/signoz-deploy/pours/deployment

note() { echo "$(date -Is) $*" >> "$LOG"; }

# ── 1) Analyst console (:9000) ──────────────────────────────────────────────
if curl -sf -o /dev/null --max-time 15 http://127.0.0.1:9000/; then
  [ -f "$FAILS" ] && rm -f "$FAILS"
else
  n=$(( $(cat "$FAILS" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$FAILS"
  note "console health check failed (${n} consecutive)"
  if [ "$n" -ge 2 ]; then
    note "console unhealthy twice — restarting astrid-analyst"
    systemctl restart astrid-analyst
    rm -f "$FAILS"
    sleep 8
    curl -sf -o /dev/null --max-time 130 http://127.0.0.1:9000/ \
      || note "WARNING: console still unhealthy after restart"
  fi
fi

# ── 2) Agent (telemetry source) ─────────────────────────────────────────────
systemctl is-active --quiet astrid-agent || {
  note "astrid-agent inactive — restarting"
  systemctl restart astrid-agent
}

# ── 3) SigNoz backend (:8080) ───────────────────────────────────────────────
if ! curl -sf -o /dev/null --max-time 10 http://127.0.0.1:8080/; then
  if ! docker ps --format '{{.Names}}' | grep -q '^signoz-signoz-0$'; then
    note "signoz container down — docker compose up -d"
    (cd "$COMPOSE_DIR" && docker compose up -d) >> "$LOG" 2>&1
  fi
fi
