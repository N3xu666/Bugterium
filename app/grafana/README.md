# Bugterium Grafana Cloud Observability (Free Tier)

Zero-dependency OTLP/HTTP JSON telemetry exported by both Cloudflare Workers (`bugterium-security-monitor` and `bugterium-bff`) to Grafana Cloud Free Tier (`Mimir` metrics + `Tempo` traces), with 0 PII and under 1 ms CPU overhead.

## Exported Signals

| Service | Signal | Metrics / Spans | PII Policy |
|---|---|---|---|
| `bugterium-security-monitor` | Metrics + Cron Span | `bugterium_auth_events_24h`, `bugterium_errors_5xx_24h`, `bugterium_probes_24h`, `bugterium_probe_families_24h`, `bugterium_traffic_24h`, `bugterium_baseline_ratio`, `bugterium_worker_requests_24h` | Aggregated counts only |
| `bugterium-bff` | Request Traces + Latency | `HTTP <METHOD> <route>` spans + `bugterium_bff_request_duration_ms` | Allowlisted routes only (`/other` fallback) |

## Configure Wrangler Secrets

1. In Grafana Cloud Free Tier, open **Connections -> OpenTelemetry (OTLP)** and generate a metrics/traces API token.
2. Encode `Basic <base64(instanceId:apiToken)>` locally without committing or pasting the secret anywhere.
3. Upload secrets to both Workers:

```powershell
cd 'C:\Projects\Bugterium\app\security-monitor'
npx wrangler secret put OTLP_ENDPOINT
npx wrangler secret put OTLP_AUTH_HEADER

cd 'C:\Projects\Bugterium\app\bff'
npx wrangler secret put OTLP_ENDPOINT
npx wrangler secret put OTLP_AUTH_HEADER
```

When `OTLP_ENDPOINT` or `OTLP_AUTH_HEADER` is unset (local dev, CI, DAST), both Workers skip OTLP export cleanly.

## Import Dashboard

1. Open Grafana Cloud -> **Dashboards -> New -> Import**.
2. Upload `bugterium-observability.json` from this folder and select your Grafana Cloud Prometheus/Mimir datasource.
