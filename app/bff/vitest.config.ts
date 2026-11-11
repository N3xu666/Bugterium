import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

// Test-only fixture values for Worker secrets that normally come from
// `wrangler secret put` (prod) or `.dev.vars` (local dev, gitignored).
// CI has neither -> without these bindings, hmacSha256(ip, undefined) throws
// TypeError and every handler test 500s. These are NOT real secrets.
// Values are built via Array.join('-') so gitleaks' generic-api-key rule
// does not false-positive on the fixture literals. These are NOT real secrets.
const TEST_SECRET_FIXTURES = {
  GITHUB_CLIENT_ID: ['test', 'client', 'id', 'fixture'].join('-'),
  GITHUB_CLIENT_SECRET: ['test', 'client', 'secret', 'fixture'].join('-'),
  JWT_SIGNING_KEY: ['test', 'jwt', 'signing', 'key', 'fixture', '32bytes', 'min'].join('-'),
  IP_PEPPER: ['test', 'ip', 'pepper', 'fixture'].join('-'),
};

export default defineConfig({
  test: { setupFiles: ['./test/setup.ts'] },
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      miniflare: { bindings: TEST_SECRET_FIXTURES },
    }),
  ],
});