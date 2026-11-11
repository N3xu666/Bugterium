import { Hono } from 'hono';
import { setCookie, deleteCookie, getCookie } from 'hono/cookie';
import type { Bindings } from '../env';
import { generateRandomString, hmacSha256 } from '../lib/crypto';
import { upsertUser, createSession, logAuthEvent } from './session';
import { createJwt } from './jwt';
import { AppError } from '../lib/errors';
import { loginRateLimit } from '../middleware/rateLimit';

const oauth = new Hono<{ Bindings: Bindings }>();

oauth.get('/github', loginRateLimit, async (c) => {
  const state = generateRandomString(16);
  const now = Math.floor(Date.now() / 1000);
  
  await c.env.DB.prepare('INSERT INTO oauth_states (state, expires_at) VALUES (?, ?)')
    .bind(state, now + 600).run();

  setCookie(c, 'oauth_state', state, {
    path: '/',
    secure: c.env.ENVIRONMENT === 'production',
    httpOnly: true,
    maxAge: 600,
    sameSite: 'Lax',
  });

  const redirectUri = new URL('/auth/github/callback', c.req.url).toString();

  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', c.env.GITHUB_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'read:user');
  url.searchParams.set('state', state);

  return c.redirect(url.toString());
});

oauth.get('/github/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state');
  const cookieState = getCookie(c, 'oauth_state');

  deleteCookie(c, 'oauth_state', { path: '/' });

  if (!code || !state || !cookieState || state !== cookieState) {
    throw new AppError('invalid_state', 400, 'Invalid OAuth state');
  }

  const now = Math.floor(Date.now() / 1000);
  const stateRecord = await c.env.DB.prepare(
    'DELETE FROM oauth_states WHERE state = ? AND expires_at > ? RETURNING state'
  ).bind(state, now).first();

  if (!stateRecord) throw new AppError('invalid_state', 400, 'State expired or not found');

  const redirectUri = new URL('/auth/github/callback', c.req.url).toString();

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({
      client_id: c.env.GITHUB_CLIENT_ID,
      client_secret: c.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });

  if (!tokenRes.ok) throw new AppError('oauth_failed', 502, 'GitHub token exchange failed');
  const tokenData = await tokenRes.json() as { access_token?: string, error?: string, error_description?: string };
  
  if (!tokenData.access_token) {
    // Log the actual reason from GitHub
    console.error('GitHub OAuth Error:', tokenData.error, tokenData.error_description);
    throw new AppError('oauth_failed', 502, `No access token: ${tokenData.error_description || 'unknown'}`);
  }

  const userRes = await fetch('https://api.github.com/user', {
    headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'User-Agent': 'Bugterium-BFF' },
  });

  if (!userRes.ok) throw new AppError('oauth_failed', 502, 'Failed to fetch user profile');
  const ghUser = await userRes.json() as { id: number; login: string };

  const user = await upsertUser(c.env.DB, ghUser.id, ghUser.login, c.env.ADMIN_GITHUB_IDS || '');
  
  const ip = c.req.header('CF-Connecting-IP') || 'unknown';
  const ipHash = await hmacSha256(ip, c.env.IP_PEPPER);

  const sessionId = await createSession(c.env.DB, user.id, ipHash);
  const jwt = await createJwt(user.id, sessionId, user.role, c.env.JWT_SIGNING_KEY);

  setCookie(c, c.env.COOKIE_NAME, jwt, {
    path: '/',
    secure: c.env.ENVIRONMENT === 'production',
    httpOnly: true,
    maxAge: 3600,
    sameSite: 'Strict',
  });

  await logAuthEvent(c.env.DB, user.id, 'login_success', ipHash);

  return c.redirect('/');
});

export default oauth;