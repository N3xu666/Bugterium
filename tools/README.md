# Tools

Custom penetration testing tools used across the Bugterium walkthroughs,
methodologies, and OSCP preparation. Written in **Python**, **Go**, and **Bash**.

These are **not** replacements for established tools (nmap, feroxbuster,
linpeas, etc.). They are small wrappers, parsers, and automation scripts
built for specific phases of the workflow.

> [!CAUTION]
> **Authorized use only.**
>
> Everything in this directory is intended exclusively for:
>
> - Authorized penetration testing engagements (with written permission)
> - CTF environments (Hack The Box, OSCP labs, TryHackMe, etc.)
> - Personal lab environments you own or are authorized to test
> - Educational study and research
>
> **Do NOT use these tools against systems you do not own or have explicit
> written authorization to test.** Unauthorized access to computer systems
> is illegal in most jurisdictions and is not condoned by the author.
>
> See [`../SECURITY.md`](../SECURITY.md) for the full security policy,
> including how to report abuse or unauthorized use.

---

## Contents

| Language | Directory | Tools | Purpose |
|----------|-----------|-------|---------|
| Python | [`python/`](./python/README.md) | 1 | PoC scripts, output parsers, automation |
| Go | [`go/`](./go/README.md) | 0 | Network utilities, compiled binaries |
| Bash | [`bash/`](./bash/README.md) | 0 | System wrappers, recon helpers |

### Published tools

| Tool | Language | Description |
|------|----------|-------------|
| [`Session_Report.py`](./python/Session_Report.py) | Python | Terminal session recorder that produces a walkthrough draft. See [`python/Session_Report.md`](./python/Session_Report.md) for documentation. |

Each language directory has its own `README.md` with conventions and a
tools table specific to that language.

---

## Related Documentation

- [`../METHODOLOGY.md`](../METHODOLOGY.md) - penetration testing methodology (phases, profiles, checklists).
- [`../CHEATSHEET.md`](../CHEATSHEET.md) - quick command reference for common tools and techniques.
- [`../methodology/OSCP-Reporting.md`](../methodology/OSCP-Reporting.md) - OSCP exam reporting rules (evidence, screenshots, structure).
- [`../SECURITY.md`](../SECURITY.md) - security policy, scope, responsible disclosure, abuse reports.

---

## See Also

- [`../README.md`](../README.md) - main repository README.
- [`LICENSE`](./LICENSE) - MIT for source code under `tools/`. Markdown documentation under `tools/` (including this file) is CC BY-NC 4.0 like all other `.md` files in the repo (see [`../LICENSE`](../LICENSE)).
- [GitHub Linguist](https://github.com/github/linguist) - `.gitattributes` marks `tools/**` as `linguist-detectable=true` so the language bar chart reflects these tools.

---

*Authorized use only. For educational purposes and authorized engagements.*
