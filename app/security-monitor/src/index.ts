// Security Monitor — thin fetch handler.
// Wires together lib/security (guards, headers), lib/errors (responses),
// lib/aggregate (pure aggregation), lib/types (contracts).
//
// Fixes:
//   M-01 — aggregate() cannot ReferenceError (isolated module; try/catch wraps it)
//   M-02 (partial) — method/path guards run BEFORE GraphQL; 405/404 short-circuit
//   M-08 — baseHeaders(): nosniff, Referrer-Policy, CSP, CORP, Cache-Control
//   M-09 — errors are generic {status:'error', code}; details go to console.error
//   Env — typed via lib/types Env (was env: any)
//
// Preserved:
//   F-01..F-05 — success response JSON is IDENTICAL to pre-refactor (aggregate output)
//   GRAPHQL_QUERY — copied verbatim (no semantic changes)
//   Timeline window = 24h ending at now (handled inside aggregate)

import type { Env, GraphQLResponse, MonitorResponse } from './lib/types';
import { aggregate } from './lib/aggregate';
import { errorResponse, jsonResponse } from './lib/errors';
import { baseHeaders, corsHeaders, checkMethod, checkPath } from './lib/security';

const GRAPHQL_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql';
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

// Copied verbatim from pre-refactor src/index.ts lines 19..49.
const GRAPHQL_QUERY = `
  query getSecurityStats($accountId: String!, $startTime: Time!) {
    viewer {
      accounts(filter: {accountTag: $accountId}) {
        workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: $startTime}) {
          sum { requests errors }
        }
        byStatusCountry: httpRequestsAdaptiveGroups(limit: 100, filter: {datetime_geq: $startTime}) {
          count
          dimensions { edgeResponseStatus clientCountryName }
        }
        byHour: httpRequestsAdaptiveGroups(limit: 24, filter: {datetime_geq: $startTime}, orderBy: [datetimeHour_ASC]) {
          count
          dimensions { datetimeHour }
        }
        byPath: httpRequestsAdaptiveGroups(limit: 500, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { clientRequestPath }
        }
        byPathCountry: httpRequestsAdaptiveGroups(limit: 1000, filter: {datetime_geq: $startTime}) {
          count
          dimensions { clientRequestPath clientCountryName }
        }
        byUserAgent: httpRequestsAdaptiveGroups(limit: 50, filter: {datetime_geq: $startTime}, orderBy: [count_DESC]) {
          count
          dimensions { userAgent edgeResponseStatus }
        }
      }
    }
  }
`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');
    const cors = corsHeaders(origin);
    const base = baseHeaders();

    // Unknown Origin -> 403 (no data). No Origin (curl) -> public JSON (M-08 CORS policy).
    if (cors === null) {
      return errorResponse('forbidden_origin', 403, base);
    }
    const headers = { ...base, ...cors };

    // CORS preflight (204 No Content).
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    // Method guard (M-02): 405 before any GraphQL call.
    const methodCheck = checkMethod(request.method, headers);
    if (methodCheck.response) return methodCheck.response;

    // Path guard (M-02): 404 before any GraphQL call.
    const url = new URL(request.url);
    const pathCheck = checkPath(url.pathname, headers);
    if (pathCheck.response) return pathCheck.response;

    // Health probe (no GraphQL, no data).
    if (url.pathname === '/healthz') {
      return jsonResponse({ status: 'ok' }, 200, headers);
    }

    // ---- GraphQL fetch (only for GET/HEAD /) ----
    const startTime = new Date(Date.now() - ONE_DAY_MS).toISOString();
    let gqlResponse: Response;
    try {
      gqlResponse = await fetch(GRAPHQL_ENDPOINT, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.CF_API_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: GRAPHQL_QUERY,
          variables: { accountId: env.CF_ACCOUNT_ID, startTime },
        }),
      });
    } catch (err) {
      console.error('graphql_fetch_failed', { message: (err as Error).message });
      return errorResponse('upstream_unavailable', 502, headers);
    }

    if (!gqlResponse.ok) {
      console.error('graphql_non_2xx', { status: gqlResponse.status });
      return errorResponse('upstream_error', 502, headers);
    }

    let body: GraphQLResponse;
    try {
      body = (await gqlResponse.json()) as GraphQLResponse;
    } catch (err) {
      console.error('graphql_parse_failed', { message: (err as Error).message });
      return errorResponse('upstream_invalid', 502, headers);
    }

    // M-09: log full details, return generic to client.
    if (body.errors && body.errors.length > 0) {
      console.error('graphql_errors', { count: body.errors.length, errors: body.errors });
      return errorResponse('upstream_graphql_error', 500, headers);
    }

    const account = body.data?.viewer?.accounts?.[0];
    if (!account) {
      console.error('graphql_missing_data');
      return errorResponse('upstream_invalid', 502, headers);
    }

    // M-01: aggregate() is pure; if anything unexpected happens, catch and return generic.
    let payload: MonitorResponse;
    try {
      payload = aggregate(account, new Date());
    } catch (err) {
      console.error('aggregate_failed', { message: (err as Error).message });
      return errorResponse('internal_error', 500, headers);
    }

    return jsonResponse(payload, 200, headers);
  },
};