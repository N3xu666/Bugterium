import { describe, it, expect, vi, afterEach } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import { normalizeBffRoute, exportBffRequestTelemetry } from '../src/middleware/telemetry';

const TEST_ENDPOINT = 'https://otlp-gateway-prod-eu-west-2.grafana.net/otlp';
const TEST_AUTH = ['Basic', 'test', 'bff', 'fixture'].join('-');

describe('BFF OTLP Telemetry Middleware (TD #26)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('normalizeBffRoute enforces strict allowlist to avoid PII and cardinality blowup', () => {
    expect(normalizeBffRoute('/api/health')).toBe('/api/health');
    expect(normalizeBffRoute('/api/me/')).toBe('/api/me');
    expect(normalizeBffRoute('/auth/github/callback')).toBe('/auth/github/callback');
    expect(normalizeBffRoute('/api/users/12345')).toBe('/other');
    expect(normalizeBffRoute('/api/unknown/probe')).toBe('/other');
  });

  it('exportBffRequestTelemetry skips when OTLP config is missing', async () => {
    const fetchMock = vi.fn();
    await exportBffRequestTelemetry(
      { ENVIRONMENT: 'production' },
      'GET',
      '/api/health',
      200,
      1000,
      1020,
      fetchMock as unknown as typeof fetch,
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('exportBffRequestTelemetry emits trace span and duration metric cleanly and never throws on error', async () => {
    const fetchMock = vi.fn(async () => new Response('accepted', { status: 202 }));
    await exportBffRequestTelemetry(
      { ENVIRONMENT: 'production', OTLP_ENDPOINT: TEST_ENDPOINT, OTLP_AUTH_HEADER: TEST_AUTH },
      'GET',
      '/api/health',
      200,
      1_700_000_000_000,
      1_700_000_000_025,
      fetchMock as unknown as typeof fetch,
    );
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const throwFetch = vi.fn(async () => {
      throw new Error('network error');
    });
    await expect(
      exportBffRequestTelemetry(
        { ENVIRONMENT: 'production', OTLP_ENDPOINT: TEST_ENDPOINT, OTLP_AUTH_HEADER: TEST_AUTH },
        'POST',
        '/api/logout',
        500,
        1000,
        1010,
        throwFetch as unknown as typeof fetch,
      ),
    ).resolves.toBeUndefined();
    expect(errSpy).toHaveBeenCalled();
  });

  it('GET /api/health returns 200 without ExecutionContext when OTLP is unset', async () => {
    const req = new Request('https://bff.test/api/health');
    const res = await worker.fetch(req, env, {} as ExecutionContext);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe('ok');
  });
});
