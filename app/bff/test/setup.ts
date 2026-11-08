import { env } from 'cloudflare:test';
import { beforeAll } from 'vitest';

// Test-only schema bootstrap: the local Miniflare D1 starts empty.
// Create only the tables touched by the API during tests.
beforeAll(async () => {
  await env.DB.exec(
    'CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, count INTEGER NOT NULL);'
  );
});
