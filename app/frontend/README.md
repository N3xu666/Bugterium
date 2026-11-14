# Bugterium App Frontend (`app/frontend/`)

React 19 + TypeScript + Vite single-page application paired with the `app/bff/` Cloudflare Worker Backend-for-Frontend.

## Architecture & Integration

- Served alongside the Hono BFF API (`../bff/`) featuring GitHub OAuth authentication, Cloudflare D1 persistence, rate limiting, and audit event logging.
- Edge security telemetry is produced by `../security-monitor/` and consumed across the Bugterium platform.

## Local Development & Verification

Bind local preview/dev servers strictly to `127.0.0.1` (never `0.0.0.0`), and always pass `--ignore-scripts` when installing new packages:

```powershell
# Clean install from lockfile
npm ci

# Adding new dependencies safely
npm install <package> --ignore-scripts

# Lint and type-check + production build
npm run lint
npm run build

# Local loopback preview
npx vite preview --host 127.0.0.1
```

## CI Security Gates

Verified in [../../.github/workflows/app-ci.yml](../../.github/workflows/app-ci.yml) on pushes and pull requests to `main`:

- `Frontend Build` (`npm ci && npm run build`)
- `SAST (Semgrep)` (`p/owasp-top-ten`, `p/typescript`)
- `SCA (Trivy + npm audit)` (`HIGH,CRITICAL`, `--omit=dev --audit-level=high`)
- `DAST (ZAP baseline)` against `app/bff/` with local D1
- `Dependency Review` on pull requests

## License

Application source code is licensed under the MIT License ([../../tools/LICENSE](../../tools/LICENSE)). Repository documentation is licensed under CC BY-NC 4.0 ([../../LICENSE](../../LICENSE)).
