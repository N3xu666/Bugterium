import { Hono } from 'hono';
import { requireAuth, requireAdmin } from '../middleware/auth';
import type { Bindings, Variables } from '../env';

const admin = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// Требует и авторизации (requireAuth), и роли admin (requireAdmin)
admin.get('/', requireAuth, requireAdmin, (c) => {
  const user = c.get('user');
  return c.json({
    message: 'Welcome to the admin dashboard',
    user: user
  });
});

export default admin;