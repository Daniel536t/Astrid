#!/usr/bin/env bash
set -euo pipefail

# snapshot.sh — Capture system state for the Astrid build journal
#
# Captures into snapshots/<UTC-timestamp>/:
#   - docker compose ps (container health)
#   - last 100 lines of each SigNoz container's logs
#   - free -h, df -h (resource state)
#   - ClickHouse metric names currently stored
#   - Astrid analyst /report output (if running)
#
# Idempotent and safe to run repeatedly.

SNAPSHOT_DIR="$(cd "$(dirname "$0")" && pwd)/snapshots"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${SNAPSHOT_DIR}/${TIMESTAMP}"

# Assumed deploy directory — override with DEPLOY_DIR env var
# SigNoz is deployed from signoz-deploy/pours/deployment
DEPLOY_DIR="${DEPLOY_DIR:-$HOME/signoz-deploy/pours/deployment}"

mkdir -p "${OUT_DIR}"

echo "=== Snapshot ${TIMESTAMP} ===" | tee "${OUT_DIR}/_summary.txt"
echo "OUT_DIR=${OUT_DIR}"

# ---------------------------------------------------------------------------
# 1. docker compose ps
# ---------------------------------------------------------------------------
if [ -d "${DEPLOY_DIR}" ] && command -v docker &>/dev/null; then
  cd "${DEPLOY_DIR}"
  if [ -f docker-compose.yml ] || [ -f docker-compose.yaml ] || [ -f compose.yml ] || [ -f compose.yaml ]; then
    echo "[1/5] Capturing container health..."
    docker compose ps --all > "${OUT_DIR}/docker-ps.txt" 2>&1 || \
      docker-compose ps --all > "${OUT_DIR}/docker-ps.txt" 2>&1 || \
      echo "ERROR: docker compose ps failed" > "${OUT_DIR}/docker-ps.txt"
  else
    echo "WARN: No compose file found in ${DEPLOY_DIR}" | tee -a "${OUT_DIR}/docker-ps.txt"
  fi
else
  echo "WARN: Docker not found or deploy dir missing" > "${OUT_DIR}/docker-ps.txt"
fi

# ---------------------------------------------------------------------------
# 2. Last 100 lines of each SigNoz container's logs
# ---------------------------------------------------------------------------
echo "[2/5] Capturing container logs..."
CONTAINERS="$(docker ps --format '{{.Names}}' 2>/dev/null || true)"
if [ -n "${CONTAINERS}" ]; then
  mkdir -p "${OUT_DIR}/logs"
  while IFS= read -r cname; do
    # Sanitize container name for filename
    safe_name="$(echo "${cname}" | tr '/: ' '___')"
    docker logs --tail 100 "${cname}" > "${OUT_DIR}/logs/${safe_name}.log" 2>&1 || \
      echo "WARN: Could not fetch logs for ${cname}" >> "${OUT_DIR}/logs/errors.log"
  done <<< "${CONTAINERS}"
else
  echo "No running containers found" > "${OUT_DIR}/logs/README.txt"
fi

# ---------------------------------------------------------------------------
# 3. Resource state
# ---------------------------------------------------------------------------
echo "[3/5] Capturing resource state..."
{
  echo "=== free -h ==="
  free -h
  echo ""
  echo "=== df -h ==="
  df -h
  echo ""
  echo "=== uptime ==="
  uptime
  echo ""
  echo "=== top (summary, 5 lines) ==="
  top -b -n 1 | head -10
} > "${OUT_DIR}/resources.txt"

# ---------------------------------------------------------------------------
# 4. ClickHouse metric names
# ---------------------------------------------------------------------------
echo "[4/5] Querying ClickHouse for stored metric names..."
{
  echo "=== ClickHouse Metric Names (timestamp: ${TIMESTAMP}) ==="

  # Find the ClickHouse server container (not keeper, not user-scripts)
  CH_CONTAINER="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'clickhouse-0-0' | head -1 || true)"

  if [ -n "${CH_CONTAINER}" ]; then
    echo "Container: ${CH_CONTAINER}"

    # SigNoz uses v4 metrics schema — query samples_v4
    echo ""
    echo "--- Distinct metric names from signoz_metrics.samples_v4 ---"

    METRIC_NAMES=$(docker exec "${CH_CONTAINER}" clickhouse-client --query "
      SELECT DISTINCT metric_name
      FROM signoz_metrics.samples_v4
      WHERE metric_name != ''
      ORDER BY metric_name
      FORMAT TSVWithNames
    " 2>/dev/null) || METRIC_NAMES="WARN: Could not query"
    echo "${METRIC_NAMES}"

    echo ""
    echo "--- Metric metadata (type, temporality, unit) ---"

    docker exec "${CH_CONTAINER}" clickhouse-client --query "
      SELECT metric_name, type, temporality, is_monotonic, unit
      FROM signoz_metrics.metadata
      WHERE metric_name != ''
      ORDER BY metric_name
      FORMAT PrettyCompact
    " 2>/dev/null || echo "WARN: Could not query metadata"

    echo ""
    echo "--- Data point counts by metric (samples_v4) ---"

    docker exec "${CH_CONTAINER}" clickhouse-client --query "
      SELECT metric_name, count() AS data_points
      FROM signoz_metrics.samples_v4
      WHERE metric_name != ''
      GROUP BY metric_name
      ORDER BY metric_name
      FORMAT PrettyCompact
    " 2>/dev/null || echo "WARN: Could not count samples_v4"

    echo ""
    echo "--- Time series count by metric (time_series_v4) ---"

    docker exec "${CH_CONTAINER}" clickhouse-client --query "
      SELECT metric_name, count() AS time_series
      FROM signoz_metrics.time_series_v4
      WHERE metric_name != ''
      GROUP BY metric_name
      ORDER BY metric_name
      FORMAT PrettyCompact
    " 2>/dev/null || echo "WARN: Could not count time series"

    # Also list all non-system tables
    echo ""
    echo "--- All non-system ClickHouse tables ---"

    docker exec "${CH_CONTAINER}" clickhouse-client --query "
      SELECT database, name, engine, total_rows
      FROM system.tables
      WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema')
      ORDER BY database, name
      FORMAT PrettyCompact
    " 2>/dev/null || echo "WARN: Could not list tables"

  else
    echo "No ClickHouse server container found running"
  fi
} > "${OUT_DIR}/clickhouse-metrics.txt"

# ---------------------------------------------------------------------------
# 5. Astrid analyst /report (port 9000)
# ---------------------------------------------------------------------------
echo "[5/5] Checking Astrid analyst service..."
if curl -sf http://localhost:9000/report > "${OUT_DIR}/analyst-report.txt" 2>&1; then
  echo "Analyst report captured successfully"
else
  echo "Astrid analyst service not running on port 9000 (this is fine — may not be deployed yet)" \
    > "${OUT_DIR}/analyst-report.txt"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
{
  echo ""
  echo "=== Files captured ==="
  find "${OUT_DIR}" -type f | sort
  echo ""
  echo "=== Snapshot complete ==="
} >> "${OUT_DIR}/_summary.txt"

cat "${OUT_DIR}/_summary.txt"