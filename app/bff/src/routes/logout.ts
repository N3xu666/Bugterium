import { Hono } from 'hono';
import { getCookie, deleteCookie } from 'hono/cookie';
import { verifyJwt } from '../auth/jwt';
import type { Bindings } from '../env';

const logout = new Hono<{ Bindings: Bindings }>();

logout.post('/', async (c) => {
  const token = getCookie(c, c.env.COOKIE_NAME);
  
  if (token) {
    try {
      const payload = await verifyJwt(token, c.env.JWT_SIGNING_KEY);
      // Delete session from DB
      await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(payload.sid).run();
    } catch {
      // Ignore invalid/expired tokens on logout
    }
  }

  deleteCookie(c, c.env.COOKIE_NAME, { path: '/' });
  return c.json({ status: 'logged_out' });
});

export default logout;