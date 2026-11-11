import { describe, it, expect } from 'vitest';
import { SELF } from 'cloudflare:test';

describe('POST /api/logout', () => {
  it('accepts request with no body', async () => {
    const res = await SELF.fetch('http://localhost/api/logout', { method: 'POST' });
    expect(res.status).toBe(200);
    const data = (await res.json()) as { status: string };
    expect(data.status).toBe('logged_out');
  });

  it('accepts request with empty JSON object', async () => {
    const res = await SELF.fetch('http://localhost/api/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(200);
  });

  it('rejects unknown body fields with validation_failed', async () => {
    const res = await SELF.fetch('http://localhost/api/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ foo: 'bar' }),
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('validation_failed');
  });

  it('rejects invalid JSON with invalid_json', async () => {
    const res = await SELF.fetch('http://localhost/api/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: 'not-json',
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('invalid_json');
  });

  it('rejects oversized body with body_too_large', async () => {
    const res = await SELF.fetch('http://localhost/api/logout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"x":"' + 'a'.repeat(11000) + '"}',
    });
    expect(res.status).toBe(400);
    const data = (await res.json()) as { error: string };
    expect(data.error).toBe('body_too_large');
  });
});