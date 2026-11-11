import { describe, it, expect, vi, afterEach } from 'vitest';
import worker from '../src/index';
import type { Env, MonitorResponse, MonitorErrorResponse } from '../src/lib/types';
import fixture from './fixtures/graphql-response.json';

const ENV: Env = {
  CF_ACCOUNT_ID: 'test-account-id',
  CF_API_TOKEN: 'test-api-token',
};

const ALLOWED_ORIGIN = 'https://bugterium.pages.dev';
const UNKNOWN_ORIGIN = 'https://evil.example.com';

function makeRequest(opts: { method?: string; path?: string; origin?: string } = {}): Request {
  const { method = 'GET', path = '/', origin } = opts;
  const headers: Record<string, string> = {};
  if (origin) headers['Origin'] = origin;
  return new Request('https://monitor.test' + path, { method, headers });
}

function mockFetchSuccess(): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () =>
    new Response(JSON.stringify(fixture), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('Security Monitor - fetch handler', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('GET / (no Origin) returns 200 with MonitorResponse', async () => {
    mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ path: '/' }), ENV);
    expect(res.status).toBe(200);
    const body = (await res.json()) as MonitorResponse;
    expect(body.status).toBe('ok');
    expect(body).toHaveProperty('security_metrics');
    expect(body).toHaveProperty('timeline');
  });

  it('GET / (allowed Origin) returns 200 and echoes CORS', async () => {
    mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ path: '/', origin: ALLOWED_ORIGIN }), ENV);
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(res.headers.get('vary')).toBe('Origin');
  });

  it('POST / returns 405 without calling upstream', async () => {
    const fetchMock = mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ method: 'POST', path: '/' }), ENV);
    expect(res.status).toBe(405);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('method_not_allowed');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET /foo returns 404 without calling upstream', async () => {
    const fetchMock = mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ path: '/foo' }), ENV);
    expect(res.status).toBe(404);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('not_found');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET / (unknown Origin) returns 403 before other checks', async () => {
    const fetchMock = mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ path: '/', origin: UNKNOWN_ORIGIN }), ENV);
    expect(res.status).toBe(403);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('forbidden_origin');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET /healthz returns 200 without calling upstream', async () => {
    const fetchMock = mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ path: '/healthz' }), ENV);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { status: string };
    expect(body.status).toBe('ok');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('OPTIONS / returns 204 with CORS headers', async () => {
    const fetchMock = mockFetchSuccess();
    const res = await worker.fetch(makeRequest({ method: 'OPTIONS', path: '/', origin: ALLOWED_ORIGIN }), ENV);
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns 502 upstream_unavailable when fetch throws', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network down'); }));
    const res = await worker.fetch(makeRequest({ path: '/' }), ENV);
    expect(res.status).toBe(502);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('upstream_unavailable');
  });

  it('returns 502 upstream_error on non-2xx upstream', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('down', { status: 503 })));
    const res = await worker.fetch(makeRequest({ path: '/' }), ENV);
    expect(res.status).toBe(502);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('upstream_error');
  });

  it('returns 500 upstream_graphql_error when body.errors is non-empty', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ errors: [{ message: 'internal' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    ));
    const res = await worker.fetch(makeRequest({ path: '/' }), ENV);
    expect(res.status).toBe(500);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('upstream_graphql_error');
  });

  it('returns 502 upstream_invalid when data.viewer.accounts missing', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ data: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    ));
    const res = await worker.fetch(makeRequest({ path: '/' }), ENV);
    expect(res.status).toBe(502);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('upstream_invalid');
  });
});