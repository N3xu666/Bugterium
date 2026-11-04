import { Hono } from 'hono';
import { requireAuth } from '../middleware/auth';
import type { Bindings, Variables } from '../env';

const me = new Hono<{ Bindings: Bindings; Variables: Variables }>();

me.get('/', requireAuth, (c) => {
  return c.json(c.get('user'));
});

export default me;