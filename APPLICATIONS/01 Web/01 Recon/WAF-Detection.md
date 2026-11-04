# WAF Detection

> Detect Web Application Firewalls before testing. Knowing a WAF exists
> changes your entire approach to exploitation.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Automated Detection](#3-automated-detection)
- [4. Manual Signals](#4-manual-signals)
- [5. Vendor Fingerprint Table](#5-vendor-fingerprint-table)
- [6. If a WAF Is Detected (Lab)](#6-if-a-waf-is-detected-lab)
- [7. What NOT to Do (Production)](#7-what-not-to-do-production)
- [8. WAF on OSCP](#8-waf-on-oscp)
- [9. OSCP Notes](#9-oscp-notes)
- [10. Cheatsheet](#10-cheatsheet)
- [11. References](#11-references)

---

## 1. Overview

A Web Application Firewall (WAF) sits between the client and the web app,
inspecting HTTP requests and blocking signatures of known attacks (SQLi, XSS,
LFI, RCE, scanning tools).

**Why detect a WAF first:**

1. It changes which payloads reach the app. A blocked payload does not mean
   the vulnerability is absent - it means the WAF matched.
2. It changes tooling. `sqlmap` without tamper scripts may be blocked on
   every request; `ffuf` may trip rate limits or IP bans.
3. It changes the report. In production, a WAF detection is a finding by
   itself ("WAF present, vendor X"), and bypass requires written approval.

**Rule:** in production, if a WAF is detected, STOP attempts at bypass.
Report and ask for approval. In a lab, bypass is fair game.

---

## 2. Scope & OPSEC

> [!WARNING]
> Every action in this file is `[PROD-RISK]` in production. WAF detection
> itself does not harm the target, but it triggers SOC alerts. Announce it
> in the test plan and coordinate timing with the client.

**Lab (OSCP, HTB, PG):** no production impact. Detect freely, bypass freely.

**Production:**

- Announce WAF detection in the test plan.
- Do not attempt bypass without explicit written approval.
- If a WAF blocks you, STOP. Do not switch IPs or spoof User-Agent to evade.
- Document: detection time, source IP, WAF vendor, request that triggered
  the block. This helps the SOC correlate.

---

## 3. Automated Detection

### 3.1 wafw00f (primary tool)

```bash
pip install wafw00f
wafw00f http://target
wafw00f -a http://target              # test all known WAFs
wafw00f -l                            # list supported WAFs
wafw00f -o out.json -f json http://target
```

**Expected output:**

```text
[*] Checking http://target
[*] Generic Detection results:
[*] The site http://target seems to be behind a WAF or some sort of security solution
[*] Reason: The response has X-CDN header with value "Incapsula"
[+] The site http://target is behind Incapsula (Imperva Incapsula) WAF.
```

### 3.2 nmap NSE scripts

```bash
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target
```

**Expected output:**

```text
| http-waf-detect:
|_  Possible WAF in place
| http-waf-fingerprint:
|_  WAF: Cloudflare
```

### 3.3 whatweb

```bash
whatweb -a 1 http://target
```

**Expected output (WAF signal):**

```text
http://target [200 OK] CloudFlare, Country[UNITED STATES][US], HTML5, IP[104.16.x.x]
```

### 3.4 nuclei

```bash
# WAF detection template
nuclei -u http://target -t http/waf-detect.yaml

# Misconfiguration templates with WAF tag
nuclei -u http://target -tags waf
```

**Expected output:**

```text
[waf-detect:cloudflare] [http] [info] http://target
```

---

## 4. Manual Signals

Even without tools, several signals expose a WAF.

### 4.1 Response codes

| Code | Meaning |
|------|---------|
| 403 | Blocked by WAF (most common) |
| 406 | Not Acceptable (WAF sees a bad payload) |
| 429 | Rate limited by WAF or CDN |
| 501 | Server does not recognize method (WAF may inject) |
| 200 but body says "Access Denied" | WAF page with 200 (some vendors) |

### 4.2 Response headers

Look for WAF-specific headers (see §5).

```bash
curl -sI http://target | grep -iE 'cf-ray|x-sucuri|x-akamai|x-iinfo|server: |x-cdn'
```

### 4.3 Cookies

```bash
curl -sI http://target | grep -i 'set-cookie'
```

WAF cookies (see §5): `__cfduid`, `__cf_bm`, `incap_ses_*`, `visid_incap_*`,
`TS*` (F5).

### 4.4 Response body

WAF block pages are distinctive. Examples:

- Cloudflare: "Attention Required! | Cloudflare", ray ID in the page.
- Sucuri: "Sucuri WebSite Firewall - Access Denied".
- Imperva: "Request unsuccessful. Incapsula incident ID: ...".
- AWS WAF: 403 with "Request blocked" (generic).
- Generic: "Access Denied", "Forbidden", "Your request has been blocked".

### 4.5 Behavioral signals

- Same payload succeeds sometimes and fails others (rate-based).
- A simple `curl` works, but `sqlmap` gets 403 on every request.
- `nmap` gets 200, but `/etc/passwd` in a URL triggers 403.
- Different responses between `curl` and a browser (UA-based).

### 4.6 TLS fingerprint (JA3 / JA3S)

Some WAFs (Cloudflare, Akamai) block at the TLS layer before HTTP.

**JA3** = fingerprint of the TLS ClientHello (cipher suites, extensions,
elliptic curves, EC point formats). Different tools produce different JA3:
`curl`, `sqlmap`, `nuclei`, `python-requests` each look distinct. Blocking
by JA3 kills the request before HTTP is even parsed.

**JA3S** = fingerprint of the ServerHello. Identifies the server-side stack.

```bash
# JA3 from a live connection (python)
pip install ja3
python3 -m ja3 https://target

# curl-impersonate: force a specific browser JA3
curl-impersonate-chrome -sI https://target
curl-impersonate-firefox -sI https://target
```

**Why it matters:** if `sqlmap`/`nuclei` get 403 across the board but a
browser UA + curl-impersonate gets 200, the WAF is JA3-based.

See also: [VHosts-Subdomains.md](./VHosts-Subdomains.md),
[Fingerprinting.md](./Fingerprinting.md) §4 for related tooling.

---

## 5. Vendor Fingerprint Table

| Signal | Vendor | Notes |
|--------|--------|-------|
| `CF-RAY`, `__cfduid`, `__cf_bm`, `Server: cloudflare` | Cloudflare | Dominant WAF + CDN |
| `X-Sucuri-ID`, `X-Sucuri-Cache` | Sucuri | Common on WordPress sites |
| `X-Akamai-Transformed`, `Akamai-*` headers | Akamai | Enterprise CDN + WAF |
| `X-Iinfo`, `incap_ses_*`, `visid_incap_*`, `X-CDN: Incapsula` | Imperva (Incapsula) | Enterprise |
| `Server: BigIP`, `TS*` cookies | F5 BIG-IP ASM | Enterprise |
| `X-Powered-By-Anquanbao` | Anquanbao | Common in China |
| `X-Amzn-Trace-Id` + 403 | AWS WAF | Combined with ALB/CloudFront |
| `X-WAF-*` | Generic | Vendor varies |
| `Server: awselb/2.0` | AWS ELB | Load balancer, NOT a WAF |
| `Server: cloudflare-nginx` | Legacy Cloudflare | Older deployments |
| `X-Barracuda-*` | Barracuda WAF | Enterprise |
| `X-Citrix-*` | Citrix NetScaler | Enterprise |

---

## 6. If a WAF Is Detected (Lab)

In a lab (OSCP, HTB, PG) bypass attempts are fair game.

### 6.1 Strategy

1. **Identify the vendor.** `wafw00f -a`, header inspection, block page style.
2. **Note the trigger.** Which payload got blocked? The trigger tells you
   what the WAF is looking for.
3. **Vary encoding.** URL-encode, double-encode, unicode-encode, base64.
4. **Vary case and whitespace.** `SeLeCt`, tabs instead of spaces, `+` vs `%20`.
5. **Insert comments.** `SE/**/LECT`, `/*!50000SELECT*/` (MySQL version comment).
6. **Use alternative payloads.** See [../08 Vulnerabilities/SQLi.md](../08%20Vulnerabilities/SQLi.md)
   for signature-free variants.
7. **Adjust User-Agent.** Some WAFs block non-browser UAs at rule level.
8. **Rate-limit.** `sqlmap --delay=1`, `--random-agent`.
9. **Use tamper scripts in sqlmap.** `--tamper=space2comment,randomcase,charencode`.

### 6.2 sqlmap tamper cheat

```bash
sqlmap -u "http://target/?id=1" --batch --tamper=space2comment,randomcase,charencode
sqlmap -u "http://target/?id=1" --batch --random-agent --delay=1 --tamper=between
```

See `sqlmap --list-tampers` for the full list. Some useful ones:

| Tamper | What it does |
|--------|--------------|
| `space2comment` | Replaces space with `/**/` |
| `space2plus` | Replaces space with `+` |
| `randomcase` | Randomizes keyword case |
| `charencode` | URL-encodes every character |
| `charunicodeencode` | Unicode-encodes every character |
| `between` | Replaces `=` with `BETWEEN ... AND ...` |
| `base64encode` | Wraps payload in base64 |
| `equaltolike` | Replaces `=` with `LIKE` |

### 6.3 Testing bypass safely

Use a canary that is NOT a real attack:

```bash
# Safe canary: does the WAF block a benign union select?
curl -s "http://target/?q=union+select+1,2,3"

# If 403: WAF blocks "union select" pattern
# Try variation:
curl -s "http://target/?q=union/**/select/**/1,2,3"
curl -s "http://target/?q=UnIoN%20SeLeCt%201,2,3"
```

---

## 7. What NOT to Do (Production)

> [!WARNING]
> These actions can violate scope, trigger incident response, or get the
> tester banned from the engagement.

- Do NOT attempt bypass. Detection = report + ask.
- Do NOT flood requests to test rate limits.
- Do NOT switch source IPs to evade blocks.
- Do NOT spoof User-Agent to evade a vendor rule.
- Do NOT use aggressive payloads (SQLi, XSS) just to see if they block.
- Do NOT `sqlmap` against a production WAF without explicit permission.
- Do NOT report "WAF bypass possible" unless you actually bypassed with approval.

---

## 8. WAF on OSCP

- OSCP labs: WAF is generally absent. Skip this file during the exam.
- HTB retired machines: a few have WAF-like behavior (rate limits, blocks).
- If you hit a WAF in the exam: bypass attempts are allowed and expected.
- Focus on the trigger -> variation loop, not on tool-specific WAF docs.

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot `wafw00f` output only if the WAF affected your
> exploitation path (i.e. you had to bypass). Otherwise summarize in text.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 10. Cheatsheet

```bash
# Automated detection
wafw00f -a http://target
nmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target
whatweb -a 1 http://target
nuclei -u http://target -t http/waf-detect.yaml

# Manual signals
curl -sI http://target | grep -iE 'cf-ray|x-sucuri|x-akamai|x-iinfo|x-cdn|server'
curl -sI http://target | grep -i 'set-cookie'

# Safe canary (lab only)
curl -s "http://target/?q=union+select+1,2,3"

# sqlmap with tamper (lab only)
sqlmap -u "http://target/?id=1" --batch --tamper=space2comment,randomcase,charencode --random-agent --delay=1
```

---

## 11. References

- wafw00f - https://github.com/EnableSecurity/wafw00f
- Nuclei - https://github.com/projectdiscovery/nuclei
- sqlmap tampers - https://github.com/sqlmapproject/sqlmap/wiki/Tamper-scripts
- ja3 - https://github.com/salesforce/ja3
- curl-impersonate - https://github.com/lwthiker/curl-impersonate
- PayloadsAllTheThings - WAF bypass - https://github.com/swisskyrepo/PayloadsAllTheThings

> See also: [Fingerprinting.md](./Fingerprinting.md), [VHosts-Subdomains.md](./VHosts-Subdomains.md), [Ports-Services.md](./Ports-Services.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-10.*
