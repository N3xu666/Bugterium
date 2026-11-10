import { cloudflareTest } from '@cloudflare/vitest-plugin';
import { defineConfig } from 'vitest/config';

// Windows workaround: disable filesystem persistence to avoid
// `CreateDirectory: #5 Access is denied` on miniflare-CacheObject.
// See: https://github.com/cloudflare/workers-sdk (workerd Windows SQLite WAL bug)
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      miniflare: {
        cachePersist: false,
        isolatedStorage: false,
        kvPersist: false,
        r2Persist: false,
        durableObjectsPersist: false,
      },
    }),
  ],
});