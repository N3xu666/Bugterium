import { Hono } from 'hono';
import type { Bindings } from './env';
import { securityHeaders } from './middleware/security';
import { toErrorResponse, AppError } from './lib/errors';
import { sha256 } from './lib/crypto';
import { logAuthEvent } from './auth/session';
import { apiRateLimit } from './middleware/rateLimit';
import oauth from './auth/oauth';
import me from './routes/me';
import logout from './routes/logout';
import admin from './routes/admin';

const app = new Hono<{ Bindings: Bindings }>();

app.use('/api/*', securityHeaders);
app.use('/api/*', apiRateLimit);
app.use('/auth/*', securityHeaders);

app.route('/auth', oauth);
app.route('/api/me', me);
app.route('/api/logout', logout);
app.route('/api/admin', admin);

app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    environment: c.env.ENVIRONMENT,
    timestamp: new Date().toISOString(),
  });
});

app.notFound((c) => {
  return c.json({ error: 'not_found' }, 404);
});

app.onError(async (err, c) => {
  // Log only actual unhandled 500 errors, not expected 4xx AppErrors.
  if (!(err instanceof AppError)) {
    console.error('unhandled_error', err instanceof Error ? err.message : 'unknown');
  }
  if (c.req.path === '/auth/github/callback') {
    try {
      const ip = c.req.header('CF-Connecting-IP') || 'unknown';
      const ipHash = await sha256(ip + c.env.IP_PEPPER);
      await logAuthEvent(c.env.DB, null, 'login_fail', ipHash);
    } catch { /* never mask the original error */ }
  }
  const res = toErrorResponse(err);
  return c.json(res.body, res.status as any);
});

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    
    // Clean up expired sessions, oauth states, and rate limits
    ctx.waitUntil(env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now),
      env.DB.prepare('DELETE FROM oauth_states WHERE expires_at < ?').bind(now),
      env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(now - 3600),
      env.DB.prepare('DELETE FROM auth_events WHERE created_at < ?').bind(now - (30 * 24 * 3600))
    ]));
  }
};