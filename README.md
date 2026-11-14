# Bugterium

[![Validate](https://github.com/N3xu666/Bugterium/actions/workflows/validate.yml/badge.svg?style=flat-square)](https://github.com/N3xu666/Bugterium/actions/workflows/validate.yml)
[![App CI](https://github.com/N3xu666/Bugterium/actions/workflows/app-ci.yml/badge.svg?style=flat-square)](https://github.com/N3xu666/Bugterium/actions/workflows/app-ci.yml)
[![Deploy Site](https://github.com/N3xu666/Bugterium/actions/workflows/deploy-site.yml/badge.svg?style=flat-square)](https://github.com/N3xu666/Bugterium/actions/workflows/deploy-site.yml)
[![Live Site](https://img.shields.io/badge/Live-bugterium.pages.dev-c00030?style=flat-square)](https://bugterium.pages.dev)
[![Last commit](https://img.shields.io/github/last-commit/N3xu666/Bugterium?style=flat-square&label=last&v=4)](https://github.com/N3xu666/Bugterium/commits/main)
[![Repo size](https://img.shields.io/github/repo-size/N3xu666/Bugterium?style=flat-square&label=repo&v=5)](https://github.com/N3xu666/Bugterium)
[![Docs: CC BY-NC 4.0](https://img.shields.io/badge/Docs-CC%20BY--NC%204.0-lightgrey.svg?style=flat-square)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Code: MIT](https://img.shields.io/badge/Code-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)

Interactive cybersecurity knowledge platform, trilingual Hack The Box walkthrough library, security reference wiki, and real-time edge situational awareness suite (**Lenses Hub** at [bugterium.pages.dev](https://bugterium.pages.dev)).

New HTB machines are added as they are completed (retired only - see the stub scheme below for active machines). Reference material grows in parallel across nine security domains: Applications (`APPLICATIONS/`), Infrastructure (`INFRASTRUCTURE/`), AI Security (`AI/`), Networks (`NETWORKS/`), Anonymity/Privacy/OpSec (`ANONYMITY-PRIVACY-OPSEC/`), Cloud (`CLOUD/`), Virtualization (`VIRTUALIZATION/`), Information Security Management (`INFORMATION_SECURITY/`), and OSINT (`OSINT/`), alongside methodology notes, cheatsheets, custom tooling (`tools/`), web platform source (`site/`, `app/`), and Cloudflare infrastructure definitions (`terraform/`).

Writeups available in Az/En/Ru. Currently: **24 published (retired) + 8 active stubs** = **32 completed HTB machines** (× 3 languages = 72 published walkthrough files + 24 stub files) + **2 completed Pro Labs** (Capability Showcases).

> The published counter counts **only published walkthroughs** (machines retired on Hack The Box). Writeups for active machines are withheld per HTB ToS and stored as stubs (`Status: Completed`) until retirement.

> [!NOTE]
> All flags, passwords, hashes, and session tokens have been masked for ethical reasons.

---

## Structure

```
Bugterium/
|
+-- WRITEUPS/                                   # HTB walkthroughs, trilingual (Az, En, Ru)
|   +-- 01 Hack The Box/
|       +-- 01 All Machines/
|       +-- 02 OSCP/
|       +-- 03 Pro Labs/ (Showcases only; full writeups withheld per HTB ToS)
|
+-- APPLICATIONS/                               # application security reference
|   +-- 01 Web/
|   +-- 02 Mobile/
|   +-- 03 API/
|
+-- INFRASTRUCTURE/                             # infrastructure security reference
|   +-- 01 Active Directory/
|   +-- 02 Windows Infrastructure/
|   +-- 03 Linux Infrastructure/
|   +-- 04 Network Services/
|   +-- 05 Network Attacks/
|   +-- 06 Wireless/
|   +-- 07 Mail-and-VPN/
|
+-- AI/                                         # AI and LLM security reference
|   +-- 01 OWASP-LLM-Top-10-2026/
|   +-- 02 RAG-and-Embeddings/
|   +-- 03 Agents-and-MCP/
|   +-- 04 AI-Supply-Chain/
|   +-- 05 OSAI-Prep/
|
+-- NETWORKS/                                   # network security reference
|   +-- 01 Network Fundamentals/
|   +-- 02 Routing and Switching/
|   +-- 03 Network Devices/
|   +-- 04 Network Protocols/
|   +-- 05 Traffic Analysis and Forensics/
|   +-- 06 SDN and Modern Networks/
|
+-- ANONYMITY-PRIVACY-OPSEC/                    # anonymity, privacy and OpSec reference
|   +-- 01 Anonymous Networks/
|   +-- 02 Secure Communications/
|   +-- 03 Operating Systems and Hygiene/
|   +-- 04 Dark Web/
|   +-- 05 Anonymous Hosting/
|   +-- 06 Anonymous Crypto Operations and AML/
|   +-- 07 OpSec and Threat Models/
|   +-- 08 Attacks and Detection/
|
+-- CLOUD/                                      # cloud security reference
|   +-- 01 AWS/
|   +-- 02 Azure/
|   +-- 03 GCP/
|   +-- 04 Kubernetes-Cloud/
|   +-- 05 Serverless/
|   +-- 06 IaC/
|
+-- VIRTUALIZATION/                             # virtualization and container security reference
|   +-- 01 Hypervisors/
|   +-- 02 VM Escape/
|   +-- 03 Containers/
|   +-- 04 Sandboxes/
|   +-- 05 Orchestration/
|
+-- INFORMATION_SECURITY/                       # information security management reference
|   +-- 01 Governance and Frameworks/
|   +-- 02 Risk Management/
|   +-- 03 Compliance and Regulation/
|   +-- 04 Security Policies and Standards/
|   +-- 05 Security Awareness and Training/
|   +-- 06 Incident Response and Business Continuity/
|
+-- OSINT/                                      # open-source intelligence reference
|   +-- 01 OSINT Methodology/
|   +-- 02 People Search/
|   +-- 03 Infrastructure OSINT/
|   +-- 04 Social Media and Content/
|   +-- 05 Corporate and Business OSINT/
|
+-- site/                                       # Docusaurus portal + Lenses Hub 3D views (bugterium.pages.dev)
|   +-- scripts/                                # build-docs.py (docs sync) + sync-content.py (graph.json)
|   +-- src/components/                         # NeuralGraph, SecurityGlobe, LensesHub, AttackMatrix, AssuranceView, LiveThreats
|
+-- app/                                        # Cloudflare Workers platform services & SPA
|   +-- bff/                                    # Hono BFF API + GitHub OAuth + D1 storage + rate limiting
|   +-- frontend/                               # React 19 + TypeScript + Vite web client
|   +-- security-monitor/                       # Edge telemetry aggregator Worker + KV snapshot generator
|
+-- terraform/                                  # Cloudflare Pages & edge infrastructure as code
+-- methodology/                                # OSCP reporting rules and notes
+-- tools/                                      # custom pentest tools (Python, Go, Bash)
+-- tests/                                      # test runner + fixtures for mask.ps1 / check.ps1
```

---

## Contents

| Section | Description | Az | En | Ru |
|---------|-------------|-----|-----|-----|
| [HTB / Season 12 Aero](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/) | Special HTB season, Sep - Nov 2026 | [Az](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/01%20All%20Machines/01%20Season%2012%20%28Aero%2C%20Sep%20-%20Nov%202026%29/03%20Ru/) |
| [HTB / OSCP / Linux](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/) | Linux machines for OSCP prep | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/01%20Linux/03%20Ru/) |
| [HTB / OSCP / Windows](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/) | Windows machines for OSCP prep | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/02%20Windows/03%20Ru/) |
| [HTB / OSCP / Active Directory and Networks](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/) | AD and networks | [Az](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/01%20Az/) | [En](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/02%20En/) | [Ru](./WRITEUPS/01%20Hack%20The%20Box/02%20OSCP/03%20Active%20Directory%20and%20Networks/03%20Ru/) |
| [Web Application Security Reference](./APPLICATIONS/01%20Web/) | Stack-organized web testing reference (recon, frameworks, languages, servers, CMS, technologies, databases, vulnerabilities, OWASP Top 10) | - | [En](./APPLICATIONS/01%20Web/) | - |
| [Mobile Application Security Reference](./APPLICATIONS/02%20Mobile/) | Mobile app security reference (Android, iOS, MASVS, OWASP Mobile Top 10) | - | [En](./APPLICATIONS/02%20Mobile/) | - |
| [API Security Reference](./APPLICATIONS/03%20API/) | API Top 10, REST, GraphQL, gRPC, WebSocket, SOAP, auth, rate-limiting, API gateway | - | [En](./APPLICATIONS/03%20API/) | - |
| [Infrastructure Security Reference](./INFRASTRUCTURE/) | Active Directory, Windows, Linux, network services and attacks, wireless, mail and VPN (47 files) | - | [En](./INFRASTRUCTURE/) | - |
| [AI Security Reference](./AI/) | OWASP LLM Top 10, RAG and embeddings, agents and MCP, AI supply chain, OSAI prep (31 files) | - | [En](./AI/) | - |
| [Anonymity, Privacy and OpSec Reference](./ANONYMITY-PRIVACY-OPSEC/) | Tor, I2P, secure communications, Tails/Qubes, dark web, anonymous hosting, crypto/AML, OpSec, attacks and detection (45 files) | - | [En](./ANONYMITY-PRIVACY-OPSEC/) | - |
| [Network Security Reference](./NETWORKS/) | Network fundamentals, routing and switching, network devices, protocols, traffic analysis and forensics, SDN and modern networks (36 files) | - | [En](./NETWORKS/) | - |
| [Cloud Security Reference](./CLOUD/) | AWS, Azure, GCP, Kubernetes in the cloud, serverless, IaC (37 files) | - | [En](./CLOUD/) | - |
| [Virtualization Security Reference](./VIRTUALIZATION/) | Hypervisors, VM escape, containers, sandboxes, orchestration (32 files) | - | [En](./VIRTUALIZATION/) | - |
| [Open-Source Intelligence Reference](./OSINT/) | OSINT methodology, people search, infrastructure, social media, corporate OSINT (27 files) | - | [En](./OSINT/) | - |
| [Information Security Management Reference](./INFORMATION_SECURITY/) | Governance, risk, compliance, policies, awareness, incident response and BC (38 files) | - | [En](./INFORMATION_SECURITY/) | - |

### Other Resources

Reference material, platform components, and tooling (377 files across 9 reference categories):

| Resource | Description |
|----------|-------------|
| [Application Security Reference](./APPLICATIONS/) | Web, Mobile, and API testing reference across three subcategories (84 files total). |
| [Infrastructure Security Reference](./INFRASTRUCTURE/) | Active Directory, Windows, Linux, network services and attacks, wireless, mail and VPN. Two-track format across 7 subcategories (47 files). |
| [AI Security Reference](./AI/) | OWASP LLM Top 10 (2026), RAG and embeddings, agents and MCP, AI supply chain, OSAI prep. Two-track format across 5 subcategories (31 files). |
| [Anonymity, Privacy and OpSec Reference](./ANONYMITY-PRIVACY-OPSEC/) | Tor, I2P, secure communications, Tails/Qubes, dark web, anonymous hosting, crypto and AML, OpSec and threat models, attacks and detection (45 files). |
| [Network Security Reference](./NETWORKS/) | Network fundamentals, routing and switching, network devices, network protocols, traffic analysis and forensics, SDN and modern networks (36 files). |
| [Cloud Security Reference](./CLOUD/) | AWS, Azure, GCP, Kubernetes in the cloud, serverless, and infrastructure as code across 6 subcategories (37 files). |
| [Virtualization Security Reference](./VIRTUALIZATION/) | Hypervisors, VM escape, containers, sandboxes, orchestration across 5 subcategories (32 files). |
| [Information Security Management Reference](./INFORMATION_SECURITY/) | Governance and frameworks, risk management, compliance, policies, awareness, incident response and business continuity across 6 subcategories (38 files). |
| [OSINT](./OSINT/) | OSINT methodology, people search, infrastructure OSINT, social media, corporate OSINT (27 files). Two-track format. |
| [METHODOLOGY.md](./METHODOLOGY.md) | Engagement phases, intensity profiles, checklists. |
| [CHEATSHEET.md](./CHEATSHEET.md) | Quick command reference for common tools and techniques. |
| [methodology/OSCP-Reporting.md](./methodology/OSCP-Reporting.md) | OSCP exam reporting rules (evidence, screenshots, structure). |
| [tools/](./tools/) | Custom pentest tools (Python, Go, Bash). Includes `Session_Report.py` terminal session recorder. |
| [site/](./site/) | Docusaurus static portal and interactive **Lenses Hub** 3D visualization frontend (`NeuralGraph`, `SecurityGlobe`, `AttackMatrix`, `AssuranceView`, `LiveThreats`). |
| [app/](./app/) | Serverless edge Workers (`bff`, `security-monitor`) and Vite/React TypeScript frontend (`frontend`). |
| [terraform/](./terraform/) | Cloudflare Pages and infrastructure-as-code definitions. |

**Note:** files marked with `Status: Completed` are **stubs** for machines still active on HTB. Full writeups are published after retirement.

---

## Platform & Edge Architecture (Lenses Hub)

Bugterium operates a zero-cost, serverless edge platform built on Cloudflare Pages, Cloudflare Workers, D1, and KV:

- **Knowledge Portal & Lenses Hub (`site/`)**: Docusaurus 3 static site that compiles all `WRITEUPS/` and Reference Markdown into searchable documentation and generates `graph.json` linking documents, tools, NVD CVEs, MITRE ATT&CK, and MITRE ATLAS entities for the interactive **Lenses Hub** (`NeuralGraph`, `SecurityGlobe`, `AttackMatrix`, `AssuranceView`, `LiveThreats`). See [site/README.md](./site/README.md).
- **Backend-for-Frontend & Security Monitor (`app/`)**:
  - `app/bff/`: Hono API Worker with GitHub OAuth, D1 session storage, rate limiting, and RBAC checks.
  - `app/security-monitor/`: Cron-driven Worker producing anonymized edge telemetry snapshots (Contract v2 schema, `k >= 5` k-anonymity, `32-hex` path sanitization) consumed by Lenses Hub.
  - `app/frontend/`: React 19 + TypeScript + Vite SPA. See [app/frontend/README.md](./app/frontend/README.md).
- **Infrastructure as Code (`terraform/`)**: Cloudflare Pages project definitions (`bugterium`, `methodman`) with `prevent_destroy` lifecycle guards. See [terraform/main.tf](./terraform/main.tf).

---

## Quality & Automation

Validation is split across local gates and GitHub Actions CI workflows (all external Actions SHA-pinned):

- **Pre-commit 5-Gate Hook (`check.ps1`)** - LOCAL blocking gate (27 automated checks across secrets, 32-hex flags, masking dictionary leaks, ethical notes, encoding, CVE references, unreplaced placeholders, backslash-escaped Markdown, chat citation markers, and localization parity), alongside `tests/run-tests.ps1`, `check-anchors.ps1`, and `check-tables.ps1`.

  **Blocking errors (commit is refused):**
  - real 32-hex flags,
  - leaks from the local masking dictionary,
  - missing ethical note in a walkthrough,
  - long dashes, broken UTF-8 chars, masking artifacts,
  - unreplaced placeholder markers in docs,
  - backslash-escaped Markdown in docs,
  - chat citation markers `[citation:N]`.

  **Advisory warnings:**
  - heuristic suspicious passwords,
  - Exploitation section without a CVE reference,
  - broken relative links in docs,
  - counter drift in root README,
  - CVE table rows without a version range,
  - non-etalon References format.
- **Manual Audit (`audit.ps1` + `audit-session.ps1`)** - Deep 21-section repository verification (git state, tracked files, walkthrough structure, Attack Chain, ethical note placement, BOM encoding, language-pair parity) plus session handoff verification.
- **CI (`.github/workflows/validate.yml`)** - Runs 8 jobs on every push and on PRs to `main`: `check` (`check.ps1`), `test` (`tests/run-tests.ps1`), `tools-syntax` (`py_compile`), `tools-tests` (`pytest` + package smoke test), `gitleaks` (full history secret scan), `audit` (`audit.ps1 -SkipLocalChecks`, blocking), `anchors` (`check-anchors.ps1`), and `tables` (`check-tables.ps1`).
- **App CI (`.github/workflows/app-ci.yml`)** - Runs on pushes/PRs to `main`: TypeScript + Vitest suites for `app/bff` and `app/security-monitor`, `app/frontend` Vite production build, Semgrep SAST, Trivy SCA + `npm audit --omit=dev --audit-level=high`, OWASP ZAP Baseline DAST against local `wrangler dev`, and PR Dependency Review.
- **Deploy Site (`.github/workflows/deploy-site.yml`)** - Triggered on `Validate` success for `main`; enforces `npm audit --omit=dev --audit-level=high`, runs `build-docs.py` + `sync-content.py` + `docusaurus build`, and deploys `site/build` to Cloudflare Pages (`bugterium`).

The masking pipeline (`mask.ps1` + a local-only `masking-dict.ps1` with known sensitive values) detects and masks flags (32-hex pattern), values listed in the dictionary, and heuristic password shapes. Detection is dictionary- and pattern-based, not exhaustive - manual review remains part of the workflow.

---

## Conventions

- **`01 Az/`** - Azerbaijani writeups.
- **`02 En/`** - English writeups.
- **`03 Ru/`** - Russian writeups.
- Each writeup follows a unified structure: Attack Chain (tree) -> Machine Briefing -> Reconnaissance -> Foothold -> [Authenticated Enumeration (AD only)] -> [Exploitation] -> Lateral Movement -> Privilege Escalation -> Flags -> Key Takeaways. Exploitation sections carry a CVE reference (NVD/MITRE link or "No CVE"); key commands show expected output; OSCP machines include screenshot reminders (`> [!IMPORTANT]`).
- All sensitive data (flags, passwords, hashes) is masked.
- Machines still active on HTB are represented by **stubs** (`Status: Completed`, neutral filename). Full writeups are published after retirement.

---

## License

This repository uses a **dual-license model**:

- **Documentation** (`WRITEUPS/`, `APPLICATIONS/`, `INFRASTRUCTURE/`, `AI/`, `NETWORKS/`, `ANONYMITY-PRIVACY-OPSEC/`, `CLOUD/`, `VIRTUALIZATION/`, `INFORMATION_SECURITY/`, `OSINT/`, `methodology/`, `METHODOLOGY.md`, `CHEATSHEET.md`, `README.md`, `SECURITY.md`, and other `.md`/prose content) - [Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)](./LICENSE).
- **Source code & infrastructure** (`.py`, `.go`, `.sh`, `.ps1`, `.js`, `.jsx`, `.ts`, `.tsx`, `.css`, `.tf`, `.toml`, `.yml`) - MIT License, applies to `tools/`, `site/`, `app/`, `terraform/`, `tests/`, and root automation scripts (`check.ps1`, `mask.ps1`, `audit.ps1`, `check-anchors.ps1`, `check-tables.ps1`, `audit-session.ps1`). Full text: [tools/LICENSE](./tools/LICENSE).

See [LICENSE](./LICENSE) for the full text and the file-type rules.

---

*Personal project. For educational purposes only.*

