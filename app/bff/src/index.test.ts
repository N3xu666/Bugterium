import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';

describe('Bugterium BFF API', () => {
  it('GET /api/health returns 200 and status ok', async () => {
    const res = await SELF.fetch('http://localhost/api/health');
    expect(res.status).toBe(200);
    const data = (await res.json()) as { status: string };
    expect(data.status).toBe('ok');
  });

  it('GET /api/me returns 401 Unauthorized without cookie', async () => {
    const res = await SELF.fetch('http://localhost/api/me');
    expect(res.status).toBe(401);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('no_session');
  });

  it('GET /api/admin returns 401 Unauthorized without cookie', async () => {
    const res = await SELF.fetch('http://localhost/api/admin');
    expect(res.status).toBe(401);
  });
});