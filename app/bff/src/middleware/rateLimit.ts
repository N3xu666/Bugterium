import { createMiddleware } from 'hono/factory';
import type { Bindings } from '../env';
import { RateLimited } from '../lib/errors';
import { hmacSha256 } from '../lib/crypto';

/**
 * D1-based rate limiter factory (ASVS 3.1).
 * Key = prefix + sha256(ip + IP_PEPPER) - never the raw IP (ASVS 3.2).
 * Atomic UPSERT: reset count if window expired, otherwise increment.
 */
export function createRateLimiter(prefix: string, maxAttempts: number, windowSize = 60) {
  return createMiddleware<{ Bindings: Bindings }>(async (c, next) => {
    const ip = c.req.header('CF-Connecting-IP') || 'unknown';
    const ipHash = await hmacSha256(ip, c.env.IP_PEPPER);
    const key = `${prefix}:${ipHash}`;
    const now = Math.floor(Date.now() / 1000);

    const result = await c.env.DB.prepare(`
      INSERT INTO rate_limits (key, window_start, count)
      VALUES (?, ?, 1)
      ON CONFLICT(key) DO UPDATE SET
        count = CASE WHEN window_start < ? THEN 1 ELSE count + 1 END,
        window_start = CASE WHEN window_start < ? THEN ? ELSE window_start END
      RETURNING count
    `).bind(key, now, now - windowSize, now - windowSize, now).first<{ count: number }>();

    if (result && result.count > maxAttempts) {
      throw new RateLimited('too_many_requests', 'Too many requests. Try again later.');
    }

    await next();
  });
}

/** Login: 10 attempts per minute per IP. */
export const loginRateLimit = createRateLimiter('login', 10);

/** General API: 100 requests per minute per IP. */
export const apiRateLimit = createRateLimiter('api', 100);
