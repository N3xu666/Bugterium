// BFF -> Grafana Cloud OTLP trace + latency exporter (Free-Tier safe, 0 PII).
// Uses strict route allowlisting so arbitrary 404 paths never inflate Grafana series cardinality.

import { createMiddleware } from 'hono/factory';
import type { Bindings } from '../env';
import {
  type OtlpConfig,
  exportOtlpMetrics,
  exportOtlpSpans,
  gaugeMetric,
  generateHexId,
  intAttr,
  strAttr,
} from '../../../shared/otlp';

const ALLOWED_ROUTES = new Set<string>([
  '/api/health',
  '/api/me',
  '/api/logout',
  '/api/admin',
  '/auth/github',
  '/auth/github/callback',
]);

export function normalizeBffRoute(pathname: string): string {
  const clean = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
  return ALLOWED_ROUTES.has(clean) ? clean : '/other';
}

export async function exportBffRequestTelemetry(
  env: Pick<Bindings, 'OTLP_ENDPOINT' | 'OTLP_AUTH_HEADER' | 'ENVIRONMENT'>,
  method: string,
  route: string,
  statusCode: number,
  startMs: number,
  endMs: number,
  fetchImpl?: typeof fetch,
): Promise<void> {
  const cfg: OtlpConfig = {
    endpoint: env.OTLP_ENDPOINT,
    authHeader: env.OTLP_AUTH_HEADER,
  };
  if (!cfg.endpoint || !cfg.authHeader) return;

  const durationMs = Math.max(0, endMs - startMs);
  const statusClass = `${Math.floor(statusCode / 100)}xx`;
  const attrs = [
    strAttr('http.method', method),
    strAttr('http.route', route),
    intAttr('http.status_code', statusCode),
    strAttr('deployment.environment', env.ENVIRONMENT || 'production'),
  ];

  const span = {
    traceId: generateHexId(16),
    spanId: generateHexId(8),
    name: `HTTP ${method} ${route}`,
    kind: 2,
    startTimeMs: startMs,
    endTimeMs: endMs,
    attributes: attrs,
    statusCode: (statusCode >= 500 ? 2 : 1) as 1 | 2,
  };

  const metrics = [
    gaugeMetric('bugterium_bff_request_duration_ms', 'BFF endpoint response latency in ms', 'ms', [
      { timeMs: endMs, value: durationMs, attributes: [strAttr('route', route), strAttr('status_class', statusClass)] },
    ]),
  ];

  await Promise.all([
    exportOtlpSpans(cfg, 'bugterium-bff', [span], fetchImpl),
    exportOtlpMetrics(cfg, 'bugterium-bff', metrics, fetchImpl),
  ]);
}

export const bffTelemetry = createMiddleware<{ Bindings: Bindings }>(async (c, next) => {
  const startMs = Date.now();
  try {
    await next();
  } finally {
    if (c.env.OTLP_ENDPOINT && c.env.OTLP_AUTH_HEADER) {
      const endMs = Date.now();
      const route = normalizeBffRoute(new URL(c.req.url).pathname);
      const status = c.res?.status ?? 500;
      const promise = exportBffRequestTelemetry(c.env, c.req.method, route, status, startMs, endMs);
      let execCtx: { waitUntil?: (p: Promise<unknown>) => void } | undefined;
      try {
        execCtx = c.executionCtx;
      } catch {
        // Direct fetch tests without ExecutionContext fall through cleanly.
      }
      if (execCtx && typeof execCtx.waitUntil === 'function') {
        execCtx.waitUntil(promise);
      }
    }
  }
});
