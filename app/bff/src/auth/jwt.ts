import { sign, verify } from 'hono/jwt';
import { Unauthorized } from '../lib/errors';

export type JwtPayload = {
  sub: string; // user id
  sid: string; // session id
  role: string;
  iat: number;
  exp: number;
};

export async function createJwt(userId: number, sessionId: string, role: string, secret: string): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600; // 1 hour
  return await sign({ sub: userId.toString(), sid: sessionId, role, iat, exp }, secret);
}

export async function verifyJwt(token: string, secret: string): Promise<JwtPayload> {
  try {
    // Alg pinning explicitly prevents 'none' alg and HS/RS confusion
    const payload = await verify(token, secret, 'HS256') as JwtPayload;
    return payload;
  } catch {
    throw new Unauthorized('invalid_token', 'Invalid or expired token');
  }
}