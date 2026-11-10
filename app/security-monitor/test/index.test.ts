import { describe, it, expect } from 'vitest';
import worker from '../src/index';

describe('Security Monitor — smoke', () => {
  it('module exports a fetch handler (Cloudflare Worker contract)', () => {
    expect(worker).toBeDefined();
    expect(typeof worker.fetch).toBe('function');
  });
});