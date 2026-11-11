// Security Monitor — handler tests (Phase 1: KV snapshot + cron).
// fetch(): reads KV only, 0 GraphQL (M-02 fix).
// scheduled(): fetches GraphQL, writes KV, marks stale on failure.

import { describe, it, expect, vi, afterEach } from 'vitest';
import worker from '../src/index';
import type { Env, MonitorResponse, MonitorErrorResponse, SnapshotResponse } from '../src/lib/types';
import fixture from './fixtures/graphql-response.json';

const ALLOWED_ORIGIN = 'https://bugterium.pages.dev';
const UNKNOWN_ORIGIN = 'https://evil.example.com';

interface MockKV {
  _store: Map<string, string>;
  get: ReturnType<typeof vi.fn>;
  put: ReturnType<typeof vi.fn>;
}

function makeKV(initial?: Record<string, string>): MockKV {
  const store = new Map<string, string>(Object.entries(initial ?? {}));
  return {
    _store: store,
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => { store.set(key, value); }),
  };
}

function makeEnv(kv: MockKV): Env {
  return {
    CF_ACCOUNT_ID: 'test-account-id',
    CF_API_TOKEN: 'test-api-token',
    MONITOR_KV: kv as unknown as KVNamespace,
  };
}

function makeRequest(opts: { method?: string; path?: string; origin?: string } = {}): Request {
  const { method = 'GET', path = '/', origin } = opts;
  const headers: Record<string, string> = {};
  if (origin) headers['Origin'] = origin;
  return new Request('https://monitor.test' + path, { method, headers });
}

function fixtureAccount() {
  return (fixture as { data: { viewer: { accounts: unknown[] } } }).data.viewer.accounts[0];
}

function validSnapshotFixture(): string {
  const snap: Partial<SnapshotResponse> = {
    status: 'ok',
    timestamp: '2026-11-10T16:30:00.000Z',
    schema_version: '2.0',
    meta: {
      generated_at: '2026-11-10T16:30:00.000Z',
      window_start: '2026-11-09T16:30:00.000Z',
      window_end: '2026-11-10T16:30:00.000Z',
      stale: false,
      sampled: false,
      quota_warning: false,
    },
    security_metrics: { worker_requests_24h: 0, worker_errors_24h: 0, blocked_403: 0, blocked_429: 0, client_errors_4xx: 0, server_errors_5xx: 0, health_percent: '100.0' },
    status_breakdown: [],
    geo_data: [],
    attacks_by_country: [],
    timeline: [],
    path_data: { attacks: [], benign: [], correlations: {} },
    user_agent_data: { traffic: [], attacks: [] },
  };
  return JSON.stringify(snap);
}

function mockGraphQLSuccess(): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () =>
    new Response(JSON.stringify(fixture), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

function mockGraphQLThrow(): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () => { throw new Error('network down'); });
  vi.stubGlobal('fetch', fn);
  return fn;
}

function mockGraphQLStatus(status: number): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () => new Response('down', { status }));
  vi.stubGlobal('fetch', fn);
  return fn;
}

function mockGraphQLErrors(): ReturnType<typeof vi.fn> {
  const fn = vi.fn(async () =>
    new Response(JSON.stringify({ errors: [{ message: 'internal' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', fn);
  return fn;
}

describe('Security Monitor — fetch handler (Phase 1: KV snapshot)', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('GET / with valid snapshot in KV returns 200 with MonitorResponse (0 GraphQL)', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const fetchMock = mockGraphQLSuccess();
    const res = await worker.fetch(makeRequest({ path: '/' }), makeEnv(kv));
    expect(res.status).toBe(200);
    const body = (await res.json()) as MonitorResponse;
    expect(body.status).toBe('ok');
    expect(body).toHaveProperty('security_metrics');
    expect(body).toHaveProperty('timeline');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('ACCEPTANCE M-02: 100 requests = 0 GraphQL calls', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const fetchMock = mockGraphQLSuccess();
    const env = makeEnv(kv);
    for (let i = 0; i < 100; i++) {
      const res = await worker.fetch(makeRequest({ path: '/' }), env);
      expect(res.status).toBe(200);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET / with empty KV returns 503 snapshot_unavailable (no GraphQL)', async () => {
    const kv = makeKV();
    const fetchMock = mockGraphQLSuccess();
    const res = await worker.fetch(makeRequest({ path: '/' }), makeEnv(kv));
    expect(res.status).toBe(503);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('snapshot_unavailable');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET / with corrupt KV returns 503 snapshot_corrupt', async () => {
    const kv = makeKV({ 'snapshot:latest': 'not-json' });
    const fetchMock = mockGraphQLSuccess();
    const res = await worker.fetch(makeRequest({ path: '/' }), makeEnv(kv));
    expect(res.status).toBe(503);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('snapshot_corrupt');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('GET / with KV.get throwing returns 503 kv_unavailable', async () => {
    const kv = makeKV();
    kv.get.mockRejectedValueOnce(new Error('kv down'));
    const res = await worker.fetch(makeRequest({ path: '/' }), makeEnv(kv));
    expect(res.status).toBe(503);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('kv_unavailable');
  });

  it('GET / (allowed Origin) echoes CORS', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const res = await worker.fetch(makeRequest({ path: '/', origin: ALLOWED_ORIGIN }), makeEnv(kv));
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN);
    expect(res.headers.get('vary')).toBe('Origin');
  });

  it('POST / returns 405 without reading KV', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const res = await worker.fetch(makeRequest({ method: 'POST', path: '/' }), makeEnv(kv));
    expect(res.status).toBe(405);
    const body = (await res.json()) as MonitorErrorResponse;
    expect(body.code).toBe('method_not_allowed');
    expect(kv.get).not.toHaveBeenCalled();
  });

  it('GET /foo returns 404 without reading KV', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const res = await worker.fetch(makeRequest({ path: '/foo' }), makeEnv(kv));
    expect(res.status).toBe(404);
    expect(kv.get).not.toHaveBeenCalled();
  });

  it('GET / (unknown Origin) returns 403 before KV read', async () => {
    const kv = makeKV({ 'snapshot:latest': validSnapshotFixture() });
    const res = await worker.fetch(makeRequest({ path: '/', origin: UNKNOWN_ORIGIN }), makeEnv(kv));
    expect(res.status).toBe(403);
    expect(kv.get).not.toHaveBeenCalled();
  });

  it('GET /healthz returns 200 without reading KV', async () => {
    const kv = makeKV();
    const res = await worker.fetch(makeRequest({ path: '/healthz' }), makeEnv(kv));
    expect(res.status).toBe(200);
    expect(kv.get).not.toHaveBeenCalled();
  });

  it('OPTIONS / returns 204', async () => {
    const kv = makeKV();
    const res = await worker.fetch(
      makeRequest({ method: 'OPTIONS', path: '/', origin: ALLOWED_ORIGIN }),
      makeEnv(kv),
    );
    expect(res.status).toBe(204);
    expect(kv.get).not.toHaveBeenCalled();
  });
});

describe('Security Monitor — scheduled (cron collector)', () => {
  const CTRL = {} as ScheduledController;

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('successful GraphQL -> writes snapshot to KV with schema_version 2.0 and meta', async () => {
    mockGraphQLSuccess();
    const kv = makeKV();
    await worker.scheduled(CTRL, makeEnv(kv));
    expect(kv.put).toHaveBeenCalledTimes(1);
    const raw = kv._store.get('snapshot:latest');
    expect(raw).toBeDefined();
    const snap = JSON.parse(raw!) as SnapshotResponse;
    expect(snap.schema_version).toBe('2.0');
    expect(snap.meta.stale).toBe(false);
    expect(snap.meta.generated_at).toMatch(/^\d{4}-/);
    expect(snap.status).toBe('ok');
    expect(snap.security_metrics).toBeDefined();
    expect(fixtureAccount()).toBeDefined();
  });

  it('GraphQL throws -> marks previous snapshot stale (generated_at preserved)', async () => {
    const prevRaw = validSnapshotFixture();
    const prevParsed = JSON.parse(prevRaw) as SnapshotResponse;
    mockGraphQLThrow();
    const kv = makeKV({ 'snapshot:latest': prevRaw });
    await worker.scheduled(CTRL, makeEnv(kv));
    expect(kv.put).toHaveBeenCalledTimes(1);
    const snap = JSON.parse(kv._store.get('snapshot:latest')!) as SnapshotResponse;
    expect(snap.meta.stale).toBe(true);
    expect(snap.meta.generated_at).toBe(prevParsed.meta.generated_at);
  });

  it('GraphQL non-2xx -> marks previous snapshot stale', async () => {
    const prevRaw = validSnapshotFixture();
    mockGraphQLStatus(503);
    const kv = makeKV({ 'snapshot:latest': prevRaw });
    await worker.scheduled(CTRL, makeEnv(kv));
    const snap = JSON.parse(kv._store.get('snapshot:latest')!) as SnapshotResponse;
    expect(snap.meta.stale).toBe(true);
  });

  it('GraphQL errors[] -> marks previous snapshot stale', async () => {
    const prevRaw = validSnapshotFixture();
    mockGraphQLErrors();
    const kv = makeKV({ 'snapshot:latest': prevRaw });
    await worker.scheduled(CTRL, makeEnv(kv));
    const snap = JSON.parse(kv._store.get('snapshot:latest')!) as SnapshotResponse;
    expect(snap.meta.stale).toBe(true);
  });

  it('GraphQL missing data -> marks previous snapshot stale', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify({ data: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    ));
    const prevRaw = validSnapshotFixture();
    const kv = makeKV({ 'snapshot:latest': prevRaw });
    await worker.scheduled(CTRL, makeEnv(kv));
    const snap = JSON.parse(kv._store.get('snapshot:latest')!) as SnapshotResponse;
    expect(snap.meta.stale).toBe(true);
  });

  it('GraphQL failure with empty KV -> no write, no crash', async () => {
    mockGraphQLThrow();
    const kv = makeKV();
    await expect(worker.scheduled(CTRL, makeEnv(kv))).resolves.toBeUndefined();
    expect(kv.put).not.toHaveBeenCalled();
    expect(kv._store.size).toBe(0);
  });
});
