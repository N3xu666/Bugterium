import { createMiddleware } from 'hono/factory';
import type { Bindings } from '../env';

/**
 * Security headers for API responses (ASVS §3.9).
 * Note: static assets (HTML/CSS/JS) get their own headers via `_headers` in B3.
 * CSP here is minimal because API responses are JSON, not HTML.
 */
export const securityHeaders = createMiddleware<{ Bindings: Bindings }>(async (c, next) => {
  await next();

  const h = c.res.headers;

  // Prevent MIME sniffing.
  h.set('X-Content-Type-Options', 'nosniff');

  // Limit referrer leakage.
  h.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // No caching for API responses (especially auth-related).
  h.set('Cache-Control', 'no-store');

  // Restrictive CSP for any direct browser access to API (defence in depth).
  h.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");

  // HSTS only in production (localhost over HTTP would be ignored anyway, but explicit).
  if (c.env.ENVIRONMENT === 'production') {
    h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
});