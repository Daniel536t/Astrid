#!/usr/bin/env bash
# export-dashboards.sh — Export all SigNoz dashboards and alert rules as JSON
#
# Usage:
#   SIGNOZ_API_KEY="your-key" ./export-dashboards.sh
#   ./export-dashboards.sh                     # uses env var SIGNOZ_API_KEY
#
# Exports into ../configs/ as:
#   dashboards-<timestamp>.json
#   alerts-<timestamp>.json
#
# Requirements: curl, jq (jq is optional — fallback to raw JSON)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(dirname "${SCRIPT_DIR}")/configs"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

SIGNOZ_API_KEY="${SIGNOZ_API_KEY:-}"
SIGNOZ_URL="${SIGNOZ_URL:-http://localhost:8080}"

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
if [ -z "${SIGNOZ_API_KEY}" ]; then
  echo "WARN: SIGNOZ_API_KEY is not set."
  echo "      Will attempt unauthenticated requests (may fail if auth is enabled)."
  AUTH_HEADER=""
else
  # SigNoz authenticates API keys via the SIGNOZ-API-KEY header
  # (Authorization: Bearer is for user session JWTs and returns 401 for API keys)
  AUTH_HEADER="SIGNOZ-API-KEY: ${SIGNOZ_API_KEY}"
fi

if ! command -v curl &>/dev/null; then
  echo "FATAL: curl is required"
  exit 1
fi

mkdir -p "${CONFIG_DIR}"

# ---------------------------------------------------------------------------
# Helper: call SigNoz API, write output
# ---------------------------------------------------------------------------
api_get() {
  local endpoint="$1"
  local outfile="$2"
  local url="${SIGNOZ_URL}${endpoint}"

  if [ -n "${AUTH_HEADER}" ]; then
    curl -sf -H "${AUTH_HEADER}" -H "Accept: application/json" "${url}" > "${outfile}" 2>/dev/null
  else
    curl -sf -H "Accept: application/json" "${url}" > "${outfile}" 2>/dev/null
  fi

  return $?
}

# ---------------------------------------------------------------------------
# 1. Export dashboards
# ---------------------------------------------------------------------------
echo "[1/2] Exporting SigNoz dashboards..."

# The SigNoz API returns dashboards at /api/v1/dashboards
DASHBOARD_FILE="${CONFIG_DIR}/dashboards-${TIMESTAMP}.json"

if api_get "/api/v1/dashboards" "${DASHBOARD_FILE}"; then
  # Pretty-print with jq if available
  if command -v jq &>/dev/null; then
    tmpfile="$(mktemp)"
    jq '.' "${DASHBOARD_FILE}" > "${tmpfile}" 2>/dev/null && mv "${tmpfile}" "${DASHBOARD_FILE}"
    echo "  -> Wrote ${DASHBOARD_FILE}"
  else
    echo "  -> Wrote ${DASHBOARD_FILE} (install jq for pretty-print)"
  fi
else
  echo "  WARN: Failed to fetch dashboards (auth required? no dashboards yet?)"
  echo '{"error":"fetch-failed","detail":"Check SIGNOZ_API_KEY or SigNoz URL"}' > "${DASHBOARD_FILE}"
fi

# ---------------------------------------------------------------------------
# 2. Export alert / alertmanager rules
# ---------------------------------------------------------------------------
echo "[2/2] Exporting alert rules..."

ALERT_FILE="${CONFIG_DIR}/alerts-${TIMESTAMP}.json"

# SigNoz stores alert rules under /api/v1/rules
if api_get "/api/v1/rules" "${ALERT_FILE}"; then
  if command -v jq &>/dev/null; then
    tmpfile="$(mktemp)"
    jq '.' "${ALERT_FILE}" > "${tmpfile}" 2>/dev/null && mv "${tmpfile}" "${ALERT_FILE}"
    echo "  -> Wrote ${ALERT_FILE}"
  else
    echo "  -> Wrote ${ALERT_FILE} (install jq for pretty-print)"
  fi
else
  echo "  WARN: Failed to fetch alert rules"
  echo '{"error":"fetch-failed","detail":"Check SIGNOZ_API_KEY or SigNoz URL"}' > "${ALERT_FILE}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Export complete ==="
echo "  Config dir:  ${CONFIG_DIR}"
echo "  Dashboards:  ${DASHBOARD_FILE}"
echo "  Alert rules: ${ALERT_FILE}"
echo "  Timestamp:   ${TIMESTAMP}"
wc -c "${DASHBOARD_FILE}" "${ALERT_FILE}" 2>/dev/null || true