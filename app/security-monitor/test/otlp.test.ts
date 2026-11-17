import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  resolveOtlpUrl,
  toUnixNano,
  generateHexId,
  exportOtlpMetrics,
  exportOtlpSpans,
} from '../../shared/otlp';
import { buildMonitorMetrics, exportMonitorTelemetry } from '../src/lib/telemetry';
import type { SnapshotResponse } from '../src/lib/types';

const TEST_ENDPOINT = 'https://otlp-gateway-prod-eu-west-2.grafana.net/otlp';
const TEST_AUTH = ['Basic', 'test', 'otlp', 'fixture'].join('-');

function sampleSnapshot(): SnapshotResponse {
  return {
    status: 'ok',
    timestamp: '2026-11-18T00:00:00.000Z',
    schema_version: '2.0',
    meta: {
      generated_at: '2026-11-18T00:00:00.000Z',
      window_start: '2026-11-17T00:00:00.000Z',
      window_end: '2026-11-18T00:00:00.000Z',
      stale: false,
      sampled: false,
      quota_warning: false,
    },
    security_metrics: {
      worker_requests_24h: 369,
      worker_errors_24h: 0,
      blocked_403: 2,
      blocked_429: 0,
      client_errors_4xx: 35,
      server_errors_5xx: 647,
      health_percent: '72.4',
    },
    status_breakdown: [],
    geo_data: [],
    attacks_by_country: [],
    timeline: [],
    path_data: { attacks: [], benign: [], correlations: {} },
    user_agent_data: { traffic: [], attacks: [] },
    auth: {
      totals: { login_success: 3, login_fail: 1, forbidden: 2, logout: 1 },
      by_hour: [],
    },
    errors_5xx: {
      total: 10,
      platform_5xx: 9,
      app_5xx: 1,
      by_code: [],
      by_cache: [],
      by_origin_status: [],
    },
    probes: {
      total: 100,
      by_outcome: { reached: 90, not_found: 5, blocked: 3, error: 2 },
      top_paths: [],
      families: [{ family: 'hex32_probe', count: 5 }],
    },
    baseline: {
      current_24h: 200,
      previous_24h: 100,
      ratio: 2.0,
      level: 'spike',
      hourly_history: [],
    },
  };
}

describe('OTLP exporter & Security Monitor telemetry (TD #26)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('resolveOtlpUrl enforces HTTPS and blocks SSRF targets', () => {
    expect(resolveOtlpUrl(TEST_ENDPOINT, 'metrics')).toBe(`${TEST_ENDPOINT}/v1/metrics`);
    expect(resolveOtlpUrl(`${TEST_ENDPOINT}/`, 'traces')).toBe(`${TEST_ENDPOINT}/v1/traces`);

    const blocked = [
      undefined,
      '',
      'not-a-url',
      'http://otlp-gateway-prod-eu-west-2.grafana.net/otlp',
      'https://localhost:4318/otlp',
      'https://127.0.0.1/otlp',
      'https://10.0.0.5/otlp',
      'https://169.254.169.254/latest',
      'https://172.17.0.1/otlp',
      'https://192.168.1.10/otlp',
      'https://[::1]/otlp',
      'https://user:pass@otlp.grafana.net/otlp',
    ];
    for (const candidate of blocked) {
      expect(resolveOtlpUrl(candidate, 'metrics')).toBeNull();
    }
  });

  it('toUnixNano & generateHexId produce OTLP-compliant strings', () => {
    expect(toUnixNano(1_700_000_000_000)).toBe('1700000000000000000');
    expect(generateHexId(16)).toMatch(/^[0-9a-f]{32}$/);
    expect(generateHexId(8)).toMatch(/^[0-9a-f]{16}$/);
  });

  it('buildMonitorMetrics exports auth, 5xx, probes, families, baseline, and worker invocations', () => {
    const metrics = buildMonitorMetrics(sampleSnapshot(), 1_700_000_000_000);
    const names = metrics.map((m) => m.name);
    expect(names).toEqual([
      'bugterium_auth_events_24h',
      'bugterium_errors_5xx_24h',
      'bugterium_probes_24h',
      'bugterium_probe_families_24h',
      'bugterium_baseline_ratio',
      'bugterium_worker_requests_24h',
    ]);
  });

  it('exportMonitorTelemetry no-ops when OTLP secrets are unset', async () => {
    const fetchMock = vi.fn();
    await exportMonitorTelemetry({}, sampleSnapshot(), 1000, 1005, fetchMock as unknown as typeof fetch);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('exportMonitorTelemetry posts /v1/metrics and /v1/traces JSON payloads and survives HTTP errors', async () => {
    const fetchMock = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response('ok', { status: 200 }));
    await exportMonitorTelemetry(
      { OTLP_ENDPOINT: TEST_ENDPOINT, OTLP_AUTH_HEADER: TEST_AUTH },
      sampleSnapshot(),
      1_700_000_000_000,
      1_700_000_000_050,
      fetchMock as unknown as typeof fetch,
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const urls = fetchMock.mock.calls.map((c) => c[0]);
    expect(urls).toContain(`${TEST_ENDPOINT}/v1/metrics`);
    expect(urls).toContain(`${TEST_ENDPOINT}/v1/traces`);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const failFetch = vi.fn(async () => new Response('down', { status: 503 }));
    await expect(
      exportOtlpMetrics({ endpoint: TEST_ENDPOINT, authHeader: TEST_AUTH }, 'svc', buildMonitorMetrics(sampleSnapshot(), 1000), failFetch as unknown as typeof fetch),
    ).resolves.toBe(false);
    await expect(
      exportOtlpSpans(
        { endpoint: TEST_ENDPOINT, authHeader: TEST_AUTH },
        'svc',
        [{ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), name: 's', startTimeMs: 1000, endTimeMs: 1010 }],
        failFetch as unknown as typeof fetch,
      ),
    ).resolves.toBe(false);
    expect(errSpy).toHaveBeenCalled();
  });
});
