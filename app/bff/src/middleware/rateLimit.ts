import { createMiddleware } from 'hono/factory';
import type { Bindings } from '../env';
import { RateLimited } from '../lib/errors';

/**
 * Simple D1-based rate limiter (ASVS §3.1).
 * Limit: 10 requests per minute per IP for the /auth/github route.
 */
export const loginRateLimit = createMiddleware<{ Bindings: Bindings }>(async (c, next) => {
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const key = `login:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowSize = 60; // 1 minute
  const maxAttempts = 10;

  // Atomic UPSERT: reset count if window expired, otherwise increment
  const result = await c.env.DB.prepare(`
    INSERT INTO rate_limits (key, window_start, count)
    VALUES (?, ?, 1)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN window_start < ? THEN 1 ELSE count + 1 END,
      window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END
    RETURNING count
  `).bind(key, now, now - windowSize, now - windowSize, now).first<{ count: number }>();

  if (result && result.count > maxAttempts) {
    throw new RateLimited('too_many_requests', 'Too many login attempts. Try again later.');
  }

  await next();
});