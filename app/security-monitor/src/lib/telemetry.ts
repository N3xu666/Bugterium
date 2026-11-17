// Security Monitor -> Grafana Cloud OTLP exporter (Free-Tier safe, 0 PII).
// Emits aggregated Contract v2 gauges and a single cron execution trace span.

import type { Env, SnapshotResponse } from './types';
import {
  type OtlpConfig,
  type OtlpMetric,
  exportOtlpMetrics,
  exportOtlpSpans,
  gaugeMetric,
  generateHexId,
  intAttr,
  strAttr,
} from '../../../shared/otlp';

export function buildMonitorMetrics(snapshot: SnapshotResponse, timeMs: number): OtlpMetric[] {
  const metrics: OtlpMetric[] = [];

  if (snapshot.auth) {
    const t = snapshot.auth.totals;
    metrics.push(
      gaugeMetric('bugterium_auth_events_24h', '24h D1 auth_events totals by event type', '1', [
        { timeMs, value: t.login_success, attributes: [strAttr('event', 'login_success')] },
        { timeMs, value: t.login_fail, attributes: [strAttr('event', 'login_fail')] },
        { timeMs, value: t.forbidden, attributes: [strAttr('event', 'forbidden')] },
        { timeMs, value: t.logout, attributes: [strAttr('event', 'logout')] },
      ]),
    );
  }

  if (snapshot.errors_5xx) {
    metrics.push(
      gaugeMetric('bugterium_errors_5xx_24h', '24h HTTP 5xx errors by classification', '1', [
        { timeMs, value: snapshot.errors_5xx.platform_5xx, attributes: [strAttr('classification', 'platform')] },
        { timeMs, value: snapshot.errors_5xx.app_5xx, attributes: [strAttr('classification', 'app')] },
      ]),
    );
  }

  if (snapshot.probes) {
    const o = snapshot.probes.by_outcome;
    metrics.push(
      gaugeMetric('bugterium_probes_24h', '24h HTTP requests by probe outcome', '1', [
        { timeMs, value: o.reached, attributes: [strAttr('outcome', 'reached')] },
        { timeMs, value: o.not_found, attributes: [strAttr('outcome', 'not_found')] },
        { timeMs, value: o.blocked, attributes: [strAttr('outcome', 'blocked')] },
        { timeMs, value: o.error, attributes: [strAttr('outcome', 'error')] },
      ]),
    );

    if (snapshot.probes.families.length > 0) {
      metrics.push(
        gaugeMetric(
          'bugterium_probe_families_24h',
          '24h classified probe path families',
          '1',
          snapshot.probes.families.slice(0, 10).map((f) => ({
            timeMs,
            value: f.count,
            attributes: [strAttr('family', f.family)],
          })),
        ),
      );
    }
  }

  if (snapshot.traffic) {
    metrics.push(
      gaugeMetric('bugterium_traffic_24h', '24h traffic by host/class', '1', [
        { timeMs, value: snapshot.traffic.site_requests, attributes: [strAttr('segment', 'site_requests')] },
        { timeMs, value: snapshot.traffic.own_polling, attributes: [strAttr('segment', 'own_polling')] },
        { timeMs, value: snapshot.traffic.bff_requests, attributes: [strAttr('segment', 'bff_requests')] },
        { timeMs, value: snapshot.traffic.human_est, attributes: [strAttr('segment', 'human_est')] },
        { timeMs, value: snapshot.traffic.bot_est, attributes: [strAttr('segment', 'bot_est')] },
        { timeMs, value: snapshot.traffic.scanner_est, attributes: [strAttr('segment', 'scanner_est')] },
      ]),
    );
  }

  if (snapshot.baseline) {
    metrics.push(
      gaugeMetric('bugterium_baseline_ratio', '24h vs previous 24h traffic ratio', '1', [
        { timeMs, value: snapshot.baseline.ratio, attributes: [strAttr('level', snapshot.baseline.level)] },
      ]),
    );
  }

  metrics.push(
    gaugeMetric('bugterium_worker_requests_24h', '24h Cloudflare Worker invocations', '1', [
      { timeMs, value: snapshot.security_metrics.worker_requests_24h },
    ]),
  );

  return metrics;
}

export async function exportMonitorTelemetry(
  env: Pick<Env, 'OTLP_ENDPOINT' | 'OTLP_AUTH_HEADER'>,
  snapshot: SnapshotResponse,
  cronStartMs: number,
  cronEndMs: number,
  fetchImpl?: typeof fetch,
): Promise<void> {
  const cfg: OtlpConfig = {
    endpoint: env.OTLP_ENDPOINT,
    authHeader: env.OTLP_AUTH_HEADER,
  };
  if (!cfg.endpoint || !cfg.authHeader) return;

  const metrics = buildMonitorMetrics(snapshot, cronEndMs);
  const span = {
    traceId: generateHexId(16),
    spanId: generateHexId(8),
    name: 'monitor.scheduled.snapshot',
    kind: 1,
    startTimeMs: cronStartMs,
    endTimeMs: cronEndMs,
    attributes: [
      strAttr('snapshot.schema_version', snapshot.schema_version),
      intAttr('snapshot.probes_total', snapshot.probes?.total ?? 0),
      intAttr('snapshot.app_5xx', snapshot.errors_5xx?.app_5xx ?? 0),
    ],
    statusCode: (snapshot.meta.stale ? 2 : 1) as 1 | 2,
  };

  await Promise.all([
    exportOtlpMetrics(cfg, 'bugterium-security-monitor', metrics, fetchImpl),
    exportOtlpSpans(cfg, 'bugterium-security-monitor', [span], fetchImpl),
  ]);
}
