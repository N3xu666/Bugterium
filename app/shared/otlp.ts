// Zero-dependency OTLP/HTTP JSON exporter for Cloudflare Workers (Free-Tier safe).
// Emits standard OpenTelemetry /v1/metrics and /v1/traces payloads over HTTPS.
// Gracefully no-ops when OTLP secrets are unset and never throws into callers.

export interface OtlpConfig {
  endpoint?: string;
  authHeader?: string;
}

export interface OtlpAttributeValue {
  stringValue?: string;
  intValue?: string;
  doubleValue?: number;
  boolValue?: boolean;
}

export interface OtlpAttribute {
  key: string;
  value: OtlpAttributeValue;
}

export interface OtlpDataPointInput {
  timeMs: number;
  value: number;
  attributes?: OtlpAttribute[];
}

export interface OtlpMetric {
  name: string;
  description: string;
  unit: string;
  gauge: {
    dataPoints: Array<{
      attributes?: OtlpAttribute[];
      timeUnixNano: string;
      asDouble: number;
    }>;
  };
}

export interface OtlpSpanInput {
  traceId: string;
  spanId: string;
  name: string;
  kind?: number;
  startTimeMs: number;
  endTimeMs: number;
  attributes?: OtlpAttribute[];
  statusCode?: 0 | 1 | 2;
}

const DEFAULT_TIMEOUT_MS = 2500;

const PRIVATE_IPV4_RE = /^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.)/;

function isPrivateOrLocalHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (!lower || lower === 'localhost' || lower.endsWith('.local') || lower.endsWith('.internal')) {
    return true;
  }
  if (lower.startsWith('[') || lower.includes(':')) {
    return true; // Reject IPv6 literals to prevent ::1 / fc00:: / fe80:: SSRF.
  }
  return PRIVATE_IPV4_RE.test(lower);
}

// Validates OTLP_ENDPOINT against SSRF (HTTPS only, non-private host, no embedded credentials).
export function resolveOtlpUrl(
  rawEndpoint: string | undefined,
  signal: 'metrics' | 'traces',
): string | null {
  if (!rawEndpoint) return null;
  let parsed: URL;
  try {
    parsed = new URL(rawEndpoint.trim());
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    return null;
  }
  if (isPrivateOrLocalHostname(parsed.hostname)) {
    return null;
  }
  const basePath = parsed.pathname.replace(/\/+$/, '');
  const suffix = signal === 'metrics' ? '/v1/metrics' : '/v1/traces';
  return `${parsed.origin}${basePath}${suffix}`;
}

export function toUnixNano(ms: number): string {
  const safeMs = Number.isFinite(ms) && ms > 0 ? Math.trunc(ms) : 0;
  return (BigInt(safeMs) * 1_000_000n).toString();
}

export function generateHexId(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0');
  }
  return out;
}

export function strAttr(key: string, value: string): OtlpAttribute {
  return { key, value: { stringValue: value } };
}

export function intAttr(key: string, value: number): OtlpAttribute {
  return { key, value: { intValue: String(Math.trunc(value)) } };
}

export function gaugeMetric(
  name: string,
  description: string,
  unit: string,
  points: OtlpDataPointInput[],
): OtlpMetric {
  return {
    name,
    description,
    unit,
    gauge: {
      dataPoints: points.map((p) => ({
        ...(p.attributes && p.attributes.length > 0 ? { attributes: p.attributes } : {}),
        timeUnixNano: toUnixNano(p.timeMs),
        asDouble: Number.isFinite(p.value) ? p.value : 0,
      })),
    },
  };
}

async function postOtlpJson(
  config: OtlpConfig,
  signal: 'metrics' | 'traces',
  payload: unknown,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  if (!config.endpoint || !config.authHeader) {
    return false;
  }
  const targetUrl = resolveOtlpUrl(config.endpoint, signal);
  if (!targetUrl) {
    console.error('otlp_invalid_endpoint', { signal });
    return false;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);
  try {
    const res = await fetchImpl(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: config.authHeader,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    if (!res.ok) {
      console.error('otlp_export_http_error', { signal, status: res.status });
      return false;
    }
    return true;
  } catch (err) {
    console.error('otlp_export_failed', {
      signal,
      message: err instanceof Error ? err.message.slice(0, 120) : 'unknown',
    });
    return false;
  } finally {
    clearTimeout(timer);
  }
}

export async function exportOtlpMetrics(
  config: OtlpConfig,
  serviceName: string,
  metrics: OtlpMetric[],
  fetchImpl?: typeof fetch,
): Promise<boolean> {
  if (metrics.length === 0) return false;
  const payload = {
    resourceMetrics: [
      {
        resource: {
          attributes: [strAttr('service.name', serviceName)],
        },
        scopeMetrics: [
          {
            scope: { name: 'bugterium.otlp', version: '1.0.0' },
            metrics,
          },
        ],
      },
    ],
  };
  return postOtlpJson(config, 'metrics', payload, fetchImpl);
}

export async function exportOtlpSpans(
  config: OtlpConfig,
  serviceName: string,
  spans: OtlpSpanInput[],
  fetchImpl?: typeof fetch,
): Promise<boolean> {
  if (spans.length === 0) return false;
  const payload = {
    resourceSpans: [
      {
        resource: {
          attributes: [strAttr('service.name', serviceName)],
        },
        scopeSpans: [
          {
            scope: { name: 'bugterium.otlp', version: '1.0.0' },
            spans: spans.map((s) => ({
              traceId: s.traceId,
              spanId: s.spanId,
              name: s.name,
              kind: s.kind ?? 2,
              startTimeUnixNano: toUnixNano(s.startTimeMs),
              endTimeUnixNano: toUnixNano(Math.max(s.endTimeMs, s.startTimeMs)),
              ...(s.attributes && s.attributes.length > 0 ? { attributes: s.attributes } : {}),
              status: { code: s.statusCode ?? 1 },
            })),
          },
        ],
      },
    ],
  };
  return postOtlpJson(config, 'traces', payload, fetchImpl);
}
