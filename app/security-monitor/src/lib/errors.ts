// Security Monitor — error responses.
// M-09: never leak internal details. Generic {status, code} only.
// Callers MUST log the actual error via console.error before calling errorResponse.

import type { MonitorErrorResponse } from './types';

export function jsonResponse(
  body: unknown,
  status: number,
  headers: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export function errorResponse(
  code: string,
  status: number,
  headers: Record<string, string>,
): Response {
  const body: MonitorErrorResponse = { status: 'error', code };
  return jsonResponse(body, status, headers);
}