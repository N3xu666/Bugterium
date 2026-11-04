import { createMiddleware } from 'hono/factory';
import { getCookie } from 'hono/cookie';
import { verifyJwt } from '../auth/jwt';
import { Unauthorized } from '../lib/errors';
import type { Bindings, Variables } from '../env';

export const requireAuth = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  const token = getCookie(c, c.env.COOKIE_NAME);
  if (!token) throw new Unauthorized('no_session', 'No session cookie');

  const payload = await verifyJwt(token, c.env.JWT_SIGNING_KEY);

  // Check session in D1 (allows instant revocation)
  const now = Math.floor(Date.now() / 1000);
  const session = await c.env.DB.prepare(
    'SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?'
  ).bind(payload.sid, now).first<{ user_id: number }>();

  if (!session) throw new Unauthorized('session_expired', 'Session invalid or expired');

  // Fetch fresh user data (role might have changed)
  const user = await c.env.DB.prepare(
    'SELECT id, username, role FROM users WHERE id = ?'
  ).bind(session.user_id).first<{ id: number; username: string; role: 'user' | 'admin' }>();

  if (!user) throw new Unauthorized('user_not_found', 'User not found');

  c.set('user', user);
  await next();
});

export const requireAdmin = createMiddleware<{ Bindings: Bindings; Variables: Variables }>(async (c, next) => {
  const user = c.get('user');
  if (!user || user.role !== 'admin') {
    throw new Unauthorized('forbidden', 'Admin access required');
  }
  await next();
});