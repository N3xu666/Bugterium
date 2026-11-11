import { describe, it, expect } from 'vitest';
import { hmacSha256 } from './crypto';

describe('hmacSha256', () => {
  it('is deterministic (same msg + key -> same hex)', async () => {
    const a = await hmacSha256('1.2.3.4', 'pepper-A');
    const b = await hmacSha256('1.2.3.4', 'pepper-A');
    expect(a).toBe(b);
  });

  it('returns 64 lowercase hex chars (SHA-256)', async () => {
    const h = await hmacSha256('1.2.3.4', 'pepper');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
  });

  it('different key -> different hash (no reuse of sha256(ip+key))', async () => {
    const a = await hmacSha256('1.2.3.4', 'pepper-A');
    const b = await hmacSha256('1.2.3.4', 'pepper-B');
    expect(a).not.toBe(b);
  });

  it('different message -> different hash', async () => {
    const a = await hmacSha256('1.2.3.4', 'pepper');
    const b = await hmacSha256('5.6.7.8', 'pepper');
    expect(a).not.toBe(b);
  });
});