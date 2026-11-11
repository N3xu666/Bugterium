// Security Monitor — request guards and response headers.
//   M-02 (partial): method/path guards before GraphQL
//   M-08: base security headers
//   CORS: strict allowlist, Vary: Origin, unknown Origin -> 403
//   M-09: errors via errorResponse (generic only)

import { errorResponse } from './errors';

const ALLOWED_ORIGINS = new Set<string>([
  'https://bugterium.pages.dev',
  'http://localhost:3000',
]);

const ALLOWED_METHODS = new Set<string>(['GET', 'HEAD', 'OPTIONS']);
const ALLOWED_PATHS = new Set<string>(['/', '/healthz']);

export interface GuardResult {
  ok: boolean;
  response?: Response;
}

// Present on every response.
// Cache-Control: 30s public cache (Phase 1, Pass 193).
// Snapshot lives in KV, refreshed by cron every 5 min — 30s cache is safe.
export function baseHeaders(): Record<string, string> {
  return {
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'public, max-age=30',
    'Content-Security-Policy': "default-src 'none'",
    'Cross-Origin-Resource-Policy': 'cross-origin',
  };
}

// Resolve CORS for the given Origin.
//   - no Origin (curl, monitoring) -> public JSON, Vary: Origin only
//   - allowed Origin              -> echo back, full CORS headers
//   - unknown Origin              -> null; caller MUST return 403
export function corsHeaders(origin: string | null): Record<string, string> | null {
  if (!origin) {
    return { Vary: 'Origin' };
  }
  if (ALLOWED_ORIGINS.has(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      Vary: 'Origin',
    };
  }
  return null;
}

export function checkMethod(method: string, headers: Record<string, string>): GuardResult {
  if (!ALLOWED_METHODS.has(method)) {
    return { ok: false, response: errorResponse('method_not_allowed', 405, headers) };
  }
  return { ok: true };
}

export function checkPath(pathname: string, headers: Record<string, string>): GuardResult {
  if (!ALLOWED_PATHS.has(pathname)) {
    return { ok: false, response: errorResponse('not_found', 404, headers) };
  }
  return { ok: true };
}