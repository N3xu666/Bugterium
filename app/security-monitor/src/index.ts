// Security Monitor — fetch handler + cron collector.
// Phase 1 (Pass 193):
//   - fetch(): reads snapshot from KV (0 GraphQL calls per visitor)
//   - scheduled(): cron */5 fetches GraphQL once, writes snapshot to KV
// V1 contract preserved (aggregate output unchanged); v2 adds schema_version + meta.

import type { Env, GraphQLAccountData, SnapshotResponse } from './lib/types';
import { errorResponse, jsonResponse } from './lib/errors';
import { baseHeaders, corsHeaders, checkMethod, checkPath } from './lib/security';
import { fetchGraphQLAccount } from './lib/graphql';
import { buildSnapshot, markStale } from './lib/snapshot';

const KV_KEY = 'snapshot:latest';
const WINDOW_MS = 24 * 60 * 60 * 1000;

export default {
  // ---- Public API (reads KV only, never GraphQL) ----
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');
    const cors = corsHeaders(origin);
    const base = baseHeaders();

    if (cors === null) {
      return errorResponse('forbidden_origin', 403, base);
    }
    const headers = { ...base, ...cors };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    const methodCheck = checkMethod(request.method, headers);
    if (methodCheck.response) return methodCheck.response;

    const url = new URL(request.url);
    const pathCheck = checkPath(url.pathname, headers);
    if (pathCheck.response) return pathCheck.response;

    if (url.pathname === '/healthz') {
      return jsonResponse({ status: 'ok' }, 200, headers);
    }

    // ---- KV read (M-02 fix: 0 GraphQL per visitor) ----
    let raw: string | null;
    try {
      raw = await env.MONITOR_KV.get(KV_KEY);
    } catch (err) {
      console.error('kv_read_failed', { message: (err as Error).message });
      return errorResponse('kv_unavailable', 503, headers);
    }

    if (raw === null) {
      // Cron has not produced a snapshot yet.
      return errorResponse('snapshot_unavailable', 503, headers);
    }

    let snapshot: SnapshotResponse;
    try {
      snapshot = JSON.parse(raw) as SnapshotResponse;
    } catch (err) {
      console.error('snapshot_parse_failed', { message: (err as Error).message });
      return errorResponse('snapshot_corrupt', 503, headers);
    }

    return jsonResponse(snapshot, 200, headers);
  },

  // ---- Cron collector (every 5 min) ----
  async scheduled(
    _controller: ScheduledController,
    env: Env,
  ): Promise<void> {
    const windowEnd = new Date();
    const windowStart = new Date(windowEnd.getTime() - WINDOW_MS);
    const startTime = windowStart.toISOString();

    let account: GraphQLAccountData;
    try {
      account = await fetchGraphQLAccount(env, startTime);
    } catch (err) {
      console.error('scheduled_graphql_failed', { message: (err as Error).message });
      // Fallback: mark previous snapshot as stale (do NOT overwrite generated_at).
      try {
        const prevRaw = await env.MONITOR_KV.get(KV_KEY);
        if (prevRaw !== null) {
          const prev = JSON.parse(prevRaw) as SnapshotResponse;
          await env.MONITOR_KV.put(KV_KEY, JSON.stringify(markStale(prev)));
        }
      } catch (innerErr) {
        console.error('scheduled_stale_failed', { message: (innerErr as Error).message });
      }
      return;
    }

    try {
      const trafficConfig =
        env.SITE_HOST || env.MONITOR_HOST || env.BFF_HOST
          ? { siteHost: env.SITE_HOST, monitorHost: env.MONITOR_HOST, bffHost: env.BFF_HOST }
          : undefined;
      const snapshot = buildSnapshot(account, { windowStart, windowEnd, trafficConfig });
      await env.MONITOR_KV.put(KV_KEY, JSON.stringify(snapshot));
    } catch (err) {
      console.error('scheduled_write_failed', { message: (err as Error).message });
    }
  },
};
