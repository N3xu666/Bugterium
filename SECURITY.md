# Security Policy

## About This Repository

Bugterium is an enterprise-style personal cybersecurity platform comprising
trilingual Hack The Box walkthroughs (`WRITEUPS/`), nine security reference
categories, methodology guides, custom pentest tooling (`tools/`), a Docusaurus
knowledge portal with the interactive **Lenses Hub** (`site/` at `bugterium.pages.dev`),
Cloudflare Workers services (`app/bff`, `app/security-monitor`, `app/frontend`),
and Cloudflare Pages Infrastructure as Code (`terraform/`).

All published walkthroughs are **fully masked**: flags, passwords, hashes, tokens,
and session identifiers are replaced with placeholders before publication.
Real values are never committed to this repository.

---

## Sensitive Data

This repository does **not** contain:

- Real HTB flags (user, root, system)
- Real passwords, hashes, or API keys
- Real session tokens or serial numbers
- Writeups for machines that are **currently active** on Hack The Box (per HTB ToS)

Active-machine writeups are withheld and replaced with stub files
(see the `## Completed (Writeups Pending)` sections in category READMEs).

---

## Reporting a Vulnerability

If you find a security issue in this repository, please report it **privately**:

1. **Preferred:** GitHub Private Vulnerability Reporting
   - Go to the **Security** tab -> **Report a vulnerability**
   - https://github.com/N3xu666/Bugterium/security/advisories/new
2. **Email:** huseynovirshad@gmail.com
   - Subject: `[Bugterium Security] <short description>`

**Do NOT open a public GitHub issue for security problems.**

---

## Abuse Reports

If you believe any tool in this repository has been used against a system
without authorization, or you have received unsolicited traffic originating
from this code, contact: huseynovirshad@gmail.com

---

## What Qualifies

- Unmasked real secrets (flag, password, hash, token) in any file
- Unmasked real secrets in git **history** (even if removed from HEAD)
- Published writeup for an HTB machine that is **still active**
- Leaked local file paths, usernames, or other PII
- CI/CD workflow weaknesses (script injection, unpinned actions, excessive permissions)
- Broken masking that reveals a real value through placeholders
- Vulnerabilities in `site/` (XSS, DOM injection, unsafe SVG/HTML rendering) or `app/` (`app/bff` authentication, session, RBAC, D1 query injection; `app/security-monitor` telemetry handling or PII leakage)
- Sensitive credentials or state leakage in `terraform/` definitions or Worker configs

---

## What Does NOT Qualify

- Placeholders themselves (`<PASSWORD>`, `<USER_FLAG>`, etc.) - these are intentional
- Walkthroughs for **retired** HTB machines
- Theoretical issues without a concrete reproduction
- Style, formatting, or localization complaints (use a normal issue instead)

---

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix + disclosure coordination | depends on severity |

This is a personal project maintained on a best-effort basis.
No bug bounty is offered. Credit will be given in the advisory if desired.

---

## Scope

**In scope:**

- This repository and its entire git history
- Published walkthroughs (`WRITEUPS/`), reference categories (`APPLICATIONS/`, `INFRASTRUCTURE/`, `AI/`, `NETWORKS/`, `ANONYMITY-PRIVACY-OPSEC/`, `CLOUD/`, `VIRTUALIZATION/`, `INFORMATION_SECURITY/`, `OSINT/`), methodology docs, and `tools/`
- Web platform components: `site/` (portal & Lenses Hub UI), `app/` (`bff`, `security-monitor`, `frontend`), and `terraform/` IaC definitions
- Live hosted portal and edge endpoints (`bugterium.pages.dev` and associated Cloudflare Workers APIs) within non-disruptive testing boundaries
- GitHub Actions workflows in `.github/workflows/`
- README files and inline links

**Out of scope:**

- The author's personal machine or local environment
- Denial of Service (DoS/DDoS), brute-force, high-volume automated fuzzing, or resource exhaustion attacks against hosted web applications, APIs, or edge endpoints

## Build-time Dependencies and False Positives

The `site/` package uses modern build tooling (Docusaurus, Webpack, Vite). Some transitive dependencies (`serialize-javascript`, `tinypool`, `uuid`) are flagged by Dependabot for CVEs that only manifest in runtime scenarios not applicable to static site generation.

To maintain a clean `npm audit`, `overrides` in `site/package.json` force patched versions. If an override breaks the build, it is documented here as a tolerable risk rather than silently ignored.

`deepmerge` is patched via `patch-package` to fix a prototype pollution vector.
