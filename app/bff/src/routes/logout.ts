import { Hono } from 'hono';
import { getCookie, deleteCookie } from 'hono/cookie';
import { z } from 'zod';
import { verifyJwt } from '../auth/jwt';
import type { Bindings } from '../env';
import { hmacSha256 } from '../lib/crypto';
import { logAuthEvent } from '../auth/session';
import { parseJsonBody } from '../lib/validate';

const LogoutBody = z.object({});

const logout = new Hono<{ Bindings: Bindings }>();

logout.post('/', async (c) => {
  const contentLength = Number(c.req.header('content-length') || '0');
  if (contentLength > 0) {
    await parseJsonBody(c.req.raw, LogoutBody);
  }

  const token = getCookie(c, c.env.COOKIE_NAME);
  
  if (token) {
    try {
      const payload = await verifyJwt(token, c.env.JWT_SIGNING_KEY);
      // Delete session from DB
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(payload.sid).run();
      const ip = c.req.header('CF-Connecting-IP') || 'unknown';
      const ipHash = await hmacSha256(ip, c.env.IP_PEPPER);
      await logAuthEvent(c.env.DB, Number(payload.sub), 'logout', ipHash);
    } catch {
      // Ignore invalid/expired tokens on logout
    }
  }

  deleteCookie(c, c.env.COOKIE_NAME, { path: '/' });
  return c.json({ status: 'logged_out' });
});

export default logout;