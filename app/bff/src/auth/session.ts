import { D1Database } from '@cloudflare/workers-types';
import { sha256, generateRandomString } from '../lib/crypto';

export type User = { id: number; github_id: number; username: string; role: 'user' | 'admin'; };

export async function upsertUser(db: D1Database, githubId: number, username: string, adminIds: string): Promise<User> {
  const isAdmin = adminIds.split(',').map(id => id.trim()).includes(githubId.toString());
  const role = isAdmin ? 'admin' : 'user';
  const now = Math.floor(Date.now() / 1000);

  const stmt = db.prepare(`
    INSERT INTO users (github_id, username, role, created_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(github_id) DO UPDATE SET username = excluded.username, role = excluded.role
    RETURNING id, github_id, username, role
  `).bind(githubId, username, role, now);

  return await stmt.first<User>() as User;
}

export async function createSession(db: D1Database, userId: number, ipHash: string | null): Promise<string> {
  const sessionId = generateRandomString(16);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 3600;

  await db.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, created_at, ip_hash)
    VALUES (?, ?, ?, ?, ?)
  `).bind(sessionId, userId, expiresAt, now, ipHash).run();

  return sessionId;
}

export async function logAuthEvent(db: D1Database, userId: number | null, event: string, ipHash: string | null) {
  const now = Math.floor(Date.now() / 1000);
  await db.prepare(`
    INSERT INTO auth_events (user_id, event, ip_hash, created_at)
    VALUES (?, ?, ?, ?)
  `).bind(userId, event, ipHash, now).run();
}