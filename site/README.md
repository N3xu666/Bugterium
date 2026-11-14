# Bugterium Web Portal & Lenses Hub (`site/`)

Docusaurus 3 static documentation portal and interactive **Lenses Hub** 3D situational awareness suite deployed at [bugterium.pages.dev](https://bugterium.pages.dev).

## Architecture

- **Docs Sync Pipeline (`scripts/build-docs.py`)**: Converts `WRITEUPS/` and all 9 reference categories into `site/docs/` with Docusaurus frontmatter, category metadata (`_category_.json`), Pro Labs PDF certificate thumbnails, and normalized internal/GitHub cross-links.
- **Knowledge Graph Indexer (`scripts/sync-content.py`)**: Extracts tool, NVD CVE, MITRE ATT&CK, and MITRE ATLAS entities across all generated documentation into `site/static/graph.json`.
- **Lenses Hub (`src/components/`)**: Interactive operational telemetry and knowledge graph lenses (`NeuralGraph.jsx`, `SecurityGlobe.jsx`, `LensesHub.jsx`, `AttackMatrix.jsx`, `AssuranceView.jsx`, `LiveThreats.jsx`) adhering to the Bugterium canonical Light/Dark palette.

## Safe Local Development

Always install dependencies without executing arbitrary lifecycle scripts when adding new packages, and bind local servers strictly to loopback (`127.0.0.1`) rather than `0.0.0.0`:

```powershell
# Initial clean install from lockfile
npm ci

# Adding new packages safely
npm install <package> --ignore-scripts

# Build docs graph and static bundle
npm run build

# Serve locally on loopback only
npx docusaurus serve --host 127.0.0.1
```

On Windows PowerShell when running `npm start`, set `$env:WATCHPACK_POLLING='true'` if file watchers hit handle limits.

## Deployment

Production builds are automated via [../.github/workflows/deploy-site.yml](../.github/workflows/deploy-site.yml) after `Validate` succeeds on `main`. The pipeline enforces `npm audit --omit=dev --audit-level=high` before running `npm run build` and deploying `site/build/` to Cloudflare Pages (`bugterium`).

## License

Source code and configuration in `site/` (`.js`, `.jsx`, `.py`, `.css`) are licensed under the MIT License ([../tools/LICENSE](../tools/LICENSE)). Generated Markdown documentation and knowledge base content remain under CC BY-NC 4.0 ([../LICENSE](../LICENSE)).
