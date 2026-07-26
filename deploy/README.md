# Astrid — Deployment Notes

## SigNoz Installation

- **Method:** Foundry CLI (v0.2.16) → Docker Compose
- **Version:** SigNoz v0.133.0 EE
- **Location:** `/home/ubuntu/signoz-deploy/`
- **Compose file:** `pours/deployment/compose.yaml`
- **Deviations from instructions:** Used `foundryctl` (SigNoz's current recommended method) instead of `git clone` of `signoz/deploy/docker` — the latter approach is deprecated as of v0.133.

## Ports

| Port | Service | Protocol | Host Mapping |
|------|---------|----------|-------------|
| 8080 | SigNoz UI (signoz-signoz-0) | HTTP | 0.0.0.0:8080→8080 |
| 4317 | OTLP gRPC (signoz-ingester-1) | gRPC | 0.0.0.0:4317→4317 |
| 4318 | OTLP HTTP (signoz-ingester-1) | HTTP | 0.0.0.0:4318→4318 |
| 5432 | PostgreSQL (internal only) | — | signoz-network |
| 9000 | ClickHouse (internal only) | — | signoz-network |
| 1777 | pprof debug (internal only) | — | signoz-network |

## Container Status (as of deployment)

```
signoz-telemetrystore-clickhouse-0-0            Up (healthy)
signoz-metastore-postgres-0                     Up (healthy)
signoz-telemetrystore-clickhouse-user-scripts   Exited (0) — one-shot
signoz-telemetrykeeper-clickhousekeeper-0       Up (healthy)
signoz-signoz-0                                 Up (healthy)
signoz-telemetrystore-migrator                  Exited (0) — one-shot
signoz-ingester-1                               Up
```

## Startup Quirk

On first deploy, the OpAMP agent fails to register because no organization exists.
**Fix:** Register an org via `POST /api/v1/register` (done during setup).
After org creation, the ingester auto-registers and OTLP receivers activate.

## Org Credentials (created during setup)

- Email: `admin@astrid.local`
- Password: `<redacted — stored locally only, not committed>`
- Org Name: `Astrid`

## Restart Policies

All persistent services use `restart: unless-stopped`. Migrator/user-scripts use `restart: on-failure` (correct for one-shot containers). SigNoz will survive reboots.