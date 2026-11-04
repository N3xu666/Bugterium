# Fingerprinting

> Web fingerprinting reference: passive and active detection, headers, cookies, favicon hashes, WAF signals. Lab-tested commands with production-safety tags.
> Identify the stack without a browser, without triggering alerts.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Passive Fingerprinting](#3-passive-fingerprinting)
- [4. Active Fingerprinting](#4-active-fingerprinting)
- [5. Interpreting Headers](#5-interpreting-headers)
- [6. Interpreting Cookies](#6-interpreting-cookies)
- [7. Reading Error Pages](#7-reading-error-pages)
- [8. Common Paths to Probe](#8-common-paths-to-probe)
- [9. Favicon Hash (Shodan)](#9-favicon-hash-shodan)
- [10. Decision Matrix](#10-decision-matrix)
- [11. OSCP Notes + Production Notes](#11-oscp-notes--production-notes)
- [12. Cheatsheet](#12-cheatsheet)
- [13. References](#13-references)

---

## 1. Overview

Fingerprinting = identifying the stack behind an HTTP service before testing it.

**Goal:** answer these questions in order.

1. Web server? (Apache, Nginx, IIS, Tomcat, Jetty, Caddy)
2. Language? (PHP, Python, Node.js, Java, .NET, Ruby, Go)
3. Framework? (Django, Flask, Rails, Spring, Laravel, Express, ASP.NET)
4. CMS or app? (WordPress, Joomla, Drupal, Magento, custom)
5. Database? (MySQL, PostgreSQL, MSSQL, MongoDB, Redis)
6. OS hints? (Ubuntu, Debian, Windows, Alpine)

**Why no browser first:**

- Faster (curl + whatweb beats clicking).
- Doesn't cache, doesn't run JS that could alert.
- Reproducible (commands go into the report).
- Works headless on a VPS.

---

## 2. Scope & OPSEC

**Lab (OSCP, HTB, PG):** aggressive scanning is fine. No production impact.

**Production:** every request is logged. Assume the SOC sees it.

### 2.1 Tags used in this cheatsheet

| Tag | Meaning |
|-----|---------|
| `[LAB]` | Lab-only. May crash, alert, or rate-limit a production target. |
| `[PROD]` | Safe in production. Normal traffic profile. |
| `[PROD-RISK]` | Safe technically, but triggers WAF/SOC alerts. Use only with client awareness. |
| `[PROD-NO]` | Do NOT run in production without explicit written approval. |

### 2.2 Rate limiting

Rule of thumb: **<= 1 req/s in production** unless agreed otherwise.
Start at 1 req/s, increase only with written client approval.

| Tool | Lab | Production |
|------|-----|------------|
| `nmap -sV` | default (T4) | `-T2` or `-T1`, `--max-rate 10` |
| `nmap --script http-*` | default | `-T2 --max-rate 5` |
| `whatweb` | `-a 3` | `-a 1` (passive) |
| `ffuf` | default | `-rate 10 -t 5` |
| `feroxbuster` | default | `--rate-limit 10 -t 5` |
| `gobuster` | default | `--delay 100ms -t 5` |
| `httpx` | default | `-rate-limit 10 -threads 5` |
| `nikto` | default | `-Tuning 1 -maxtime 60s` (or avoid) |
| `wfuzz` | default | `-s 1 -t 5` |

### 2.3 User-Agent

- Default `curl` UA ('curl/7.x') is fine in labs.
- In production, coordinate with the client:
  - Use a documented testing UA if they provided one.
  - Otherwise use a normal browser UA to blend in:

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
curl -sI -A "$UA" http://target
```

### 2.4 Logging

Every HTTP request appears in the target's access log with:

- Source IP, timestamp, method, path, status, User-Agent.

In the report, mention: start/end time, source IPs used, tool set.
This lets the SOC correlate and confirm the test was authorized.

### 2.5 What NOT to do in production

- Do NOT run `whatweb -a 3` (aggressive, dozens of requests).
- Do NOT run `nikto` without permission (thousands of requests).
- Do NOT touch `/actuator/env`, `/actuator/heapdump`, `/debug`.
- Do NOT trigger WAF blocks on purpose ("just to see").
- Do NOT enumerate directories at >5 req/s.
- Do NOT use default `nmap -T4` against public-facing prod.

---

## 3. Passive Fingerprinting

No direct contact with the target. All info comes from third parties.

### 3.1 DNS and WHOIS

```bash
dig +short target.com
dig +short MX target.com
dig +short TXT target.com
whois target.com
host target.com
nslookup target.com
```

Look for:

- A / AAAA records (IPv4 / IPv6).
- MX (mail provider: Google Workspace, Microsoft 365, self-hosted).
- TXT (SPF, DMARC, verification tokens).
- NS (DNS provider: Cloudflare, AWS Route 53, GoDaddy).

### 3.2 Certificate Transparency (crt.sh)

```bash
# Web UI
# https://crt.sh/?q=target.com

# CLI
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u
```

Reveals subdomains that ever had a TLS certificate. Often leaks:

- staging., dev., test., admin., api., internal.
- Old / forgotten hosts.

### 3.3 Shodan / Censys / FOFA

```text
# Shodan (requires API key for CLI, free web search)
# https://www.shodan.io/search?query=hostname:target.com

# Censys
# https://search.censys.io/search?q=target.com

# FOFA (mostly Asian IPs)
# https://en.fofa.info/
```

Useful queries:

- `hostname:target.com` - all hosts pointing to the domain.
- `ssl:target.com` - by TLS certificate.
- `http.title:"Target"` - by page title.
- `http.favicon.hash:<hash>` - by favicon (see §9).

### 3.4 Google Dorking

```text
site:target.com
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql OR ext:bak OR ext:log
site:pastebin.com target.com
"target.com" inurl:github.com
```

### 3.5 WhatWeb Passive Mode `[PROD]`

```bash
whatweb -a 1 http://target
```

Level 1 = passive. Grabs what's already in the initial response.

### 3.6 TheHarvester / amass (passive) `[PROD]`

```bash
theHarvester -d target.com -b all
amass enum -passive -d target.com
```

---

## 4. Active Fingerprinting

Direct requests to the target. Use rate limits in production.

### 4.1 curl (headers) `[PROD]`

```bash
curl -sI http://target
curl -sI -L http://target              # follow redirects
curl -s -v http://target 2>&1 | head -50   # verbose (request + response)
curl -s http://target | head -50       # first 50 lines of body
```

**Expected output (headers):**

```text
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
X-Powered-By: PHP/7.4.3
Set-Cookie: PHPSESSID=abc123; path=/
Content-Type: text/html; charset=UTF-8
```

### 4.2 whatweb `[LAB]` aggressive, `[PROD]` passive

```bash
# Passive
whatweb -a 1 http://target

# Aggressive (LAB only - many requests)
whatweb -a 3 http://target

# Output to JSON for later diffing
whatweb -a 3 --log-json=out.json http://target
```

**Expected output (aggressive):**

```text
http://target [200 OK] Apache[2.4.41], Country[UNITED STATES][US],
  HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)],
  IP[10.10.10.10], JQuery[3.5.1], PHP[7.4.3], WordPress[5.8.1]
```

### 4.3 nmap HTTP scripts `[PROD with rate limit]`

```bash
nmap -sV -p 80,443,8080,8443 --script http-title,http-headers,http-methods,http-enum target

# Production: add rate limiting
nmap -sV -T2 --max-rate 10 -p 80,443 --script http-title,http-headers target
```

**Expected output:**

```text
80/tcp open  http    nginx 1.18.0
|_http-title: Welcome to ExampleApp
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
```

### 4.4 httpx `[PROD with rate limit]`

```bash
# Single target
httpx -u http://target -title -tech-detect -status-code -web-server

# From file (many targets)
cat hosts.txt | httpx -title -tech-detect -status-code -rate-limit 10
```

**Expected output:**

```text
http://target [200] [Welcome] [nginx/1.18.0, PHP/7.4.3, WordPress/5.8.1]
```

### 4.5 Wappalyzer / BuiltWith `[PROD]`

Manual / browser-based. Fine for targeted checks. Not scriptable without a paid API.

### 4.6 Favicon hash

See §9.

---

## 5. Interpreting Headers

### 5.1 Key headers

| Header | Value example | Meaning |
|--------|---------------|---------|
| `Server` | `nginx/1.18.0 (Ubuntu)` | Web server + version + OS |
| `Server` | `Apache/2.4.41 (Ubuntu)` | Apache + version + OS |
| `Server` | `Microsoft-IIS/10.0` | IIS + version (Windows) |
| `Server` | `Apache-Coyote/1.1` | Tomcat (Java) |
| `Server` | `Jetty(9.4.43)` | Jetty (Java) |
| `X-Powered-By` | `PHP/7.4.3` | PHP version |
| `X-Powered-By` | `Express` | Node.js + Express |
| `X-Powered-By` | `ASP.NET` | ASP.NET |
| `X-AspNet-Version` | `4.0.30319` | .NET Framework version |
| `X-AspNetMvc-Version` | `5.2` | MVC version |
| `X-Generator` | `WordPress 5.8.1` | WordPress |
| `X-Generator` | `Drupal 9 (https://www.drupal.org)` | Drupal |
| `X-Drupal-Cache` | `HIT` | Drupal |
| `Via` | `1.1 varnish` | Varnish cache in front |
| `X-Cache` | `HIT` / `MISS` | CDN / cache |
| `CF-RAY` | `abc123-LHR` | Cloudflare (WAF + CDN) |
| `X-Sucuri-ID` | number | Sucuri WAF |

### 5.2 Security headers (their absence matters too)

| Header | If missing... |
|--------|---------------|
| `Strict-Transport-Security` | HSTS not enforced - possible SSL strip (rare in 2026) |
| `Content-Security-Policy` | XSS impact higher |
| `X-Frame-Options` | Clickjacking possible |
| `X-Content-Type-Options` | MIME sniffing attacks |
| `Referrer-Policy` | Info leak in Referer |
| `Permissions-Policy` | Feature abuse (camera, mic, geolocation) |

Missing security headers are NOT a vulnerability by themselves. Note them for the report but do not inflate them.

---

## 6. Interpreting Cookies

Session cookie name reveals the stack.

| Cookie | Stack |
|--------|-------|
| `PHPSESSID` | PHP (raw or framework) |
| `JSESSIONID` | Java (Tomcat, Jetty, Spring, JBoss) |
| `ASP.NET_SessionId` | ASP.NET (Framework) |
| `.AspNetCore.Cookies` / `.AspNetCore.Session` | ASP.NET Core |
| `.ASPXAUTH` | ASP.NET Forms Authentication |
| `_session_id` | Ruby on Rails |
| `csrftoken` + `sessionid` | Django |
| `session` (opaque) | Flask |
| `connect.sid` | Node.js + Express |
| `laravel_session` + `XSRF-TOKEN` | Laravel |
| `wordpress_logged_in_*` / `wp-settings-*` | WordPress |
| `Joomla*` / hex hash | Joomla |
| `SESS<hash>` | Drupal |
| `Magento*` / `frontend` | Magento |
| `PrestaShop-*` | PrestaShop |
| `pmaAuth-*` | phpMyAdmin |
| `adminer_sid` | Adminer |
| `grafana_session` | Grafana |
| `jenkins-token` / `JSESSIONID.*` | Jenkins |
| `XSRF-TOKEN` + `*_session` | Laravel / Angular combos |
| Cookie value starts with `eyJ` | JWT (base64url header `{"alg":...`) |

### 6.1 JWT in a cookie

```bash
# Decode JWT header (first segment)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null
# -> {"alg":"HS256","typ":"JWT"}
```

See [../06 Technologies/JWT.md](../06%20Technologies/JWT.md) for JWT attacks.

---

## 7. Reading Error Pages

Error pages leak versions, paths, and sometimes stack traces.

### 7.1 Common triggers

```bash
curl -s http://target/does-not-exist-12345
curl -s http://target/%00
curl -s "http://target/?id=1'"
curl -s http://target/..%2f..%2fetc%2fpasswd
```

### 7.2 Stack-specific error pages

**Django DEBUG=True `[LAB]`**

- Full traceback, settings, DB creds, secret key.
- Trigger: any unhandled exception.
- See [../02 Frameworks/Django.md](../02%20Frameworks/Django.md).

**Flask Werkzeug console `[LAB - PIN RCE]`**

- Interactive debugger at `/console` when DEBUG=True.
- If PIN unknown, PIN can be computed from machine info (see Werkzeug PIN exploit).
- See [../02 Frameworks/Flask.md](../02%20Frameworks/Flask.md).

**Rails detailed errors `[LAB]`**

- Full backtrace in development mode.
- Leaks routes, gem versions, environment variables.

**Laravel Ignition CVE-2021-3129 `[LAB - RCE]`**

- `APP_DEBUG=true` + Ignition <= 2.5.1 → RCE via log file.
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-3129
- See [../02 Frameworks/Laravel.md](../02%20Frameworks/Laravel.md).

**Spring Boot Actuator `[PROD-RISK]`**

- `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings`.
- Huge info leak if exposed.
- Triggers SOC alerts immediately in production.
- See [../02 Frameworks/Spring-Boot.md](../02%20Frameworks/Spring-Boot.md).

**PHP errors / warnings `[PROD-RISK]`**

- `display_errors=On` leaks paths, versions, sometimes code.
- Trigger: malformed input.

---

## 8. Common Paths to Probe

Each tagged with production risk level.

| Path | Purpose | Tag |
|------|---------|-----|
| `/robots.txt` | Disallow list | `[PROD]` |
| `/sitemap.xml` | Site structure | `[PROD]` |
| `/security.txt` / `/.well-known/security.txt` | Contact info | `[PROD]` |
| `/humans.txt` | Team info | `[PROD]` |
| `/favicon.ico` | Favicon hash | `[PROD]` |
| `/admin` | Admin panel | `[PROD-RISK]` |
| `/login` | Login page | `[PROD]` |
| `/api` / `/api/v1` | API root | `[PROD-RISK]` |
| `/swagger` / `/swagger-ui.html` / `/openapi.json` | API docs | `[PROD-RISK]` |
| `/graphql` | GraphQL endpoint | `[PROD-RISK]` |
| `/.git/HEAD` | Git repo exposure | `[PROD-RISK]` |
| `/.env` | Env file exposure | `[PROD-RISK]` |
| `/server-status` | Apache status | `[PROD-RISK]` |
| `/nginx_status` | Nginx status | `[PROD-RISK]` |
| `/phpinfo.php` | PHP info | `[PROD-RISK]` |
| `/actuator` | Spring Boot | `[PROD-NO]` |
| `/debug` | Debug endpoint | `[PROD-NO]` |
| `/console` | Werkzeug console | `[PROD-NO]` |
| `/wp-admin` / `/wp-login.php` | WordPress | `[PROD]` |
| `/administrator` | Joomla admin | `[PROD]` |
| `/user/login` | Drupal login | `[PROD]` |
| `/manager/html` | Tomcat manager | `[PROD-RISK]` |
| `/adminer.php` / `/adminer` | Adminer | `[PROD-RISK]` |
| `/phpmyadmin` | phpMyAdmin | `[PROD]` |

---

## 9. Favicon Hash (Shodan)

Favicon hash = unique per application. Use it to find the same app on other IPs via Shodan.

### 9.1 Compute the hash

```bash
# Method 1: python mmh3
pip install mmh3
python3 -c "import mmh3, requests, codecs; r = requests.get('http://target/favicon.ico'); print(mmh3.hash(codecs.encode(r.content, 'base64')))"

# Method 2: curl + mmh3 (base64 pipeline)
curl -s http://target/favicon.ico | base64 -w 0 | python3 -c "import sys, mmh3; print(mmh3.hash(sys.stdin.read()))"

# Method 3: md5 (not Shodan-compatible but useful for correlation)
curl -s http://target/favicon.ico | md5sum
```

### 9.2 Search on Shodan

```text
http.favicon.hash:<hash>
```

Finds other hosts running the same app (e.g. all Jenkins, all GitLab, all internal tools).

---

## 10. Decision Matrix

Header/cookie signal -> likely stack -> recommended next file.

| Signal | Likely stack | Next file | Prod-safe to probe? |
|--------|--------------|-----------|---------------------|
| `Server: nginx` | Nginx (+ PHP/Python upstream) | [Servers/Nginx.md](../04%20Servers/Nginx.md) | Yes |
| `Server: Apache` | Apache (+ PHP) | [Servers/Apache.md](../04%20Servers/Apache.md) | Yes |
| `Server: Microsoft-IIS` | IIS + ASP.NET | [Servers/IIS.md](../04%20Servers/IIS.md) | Yes |
| `Server: Apache-Coyote` | Tomcat (Java) | [Servers/Tomcat.md](../04%20Servers/Tomcat.md) | Yes |
| `X-Powered-By: PHP` | PHP | [Languages/PHP.md](../03%20Languages/PHP.md) | Yes |
| `X-Powered-By: Express` | Node.js + Express | [Frameworks/Express.md](../02%20Frameworks/Express.md) | Yes |
| `X-AspNet-Version` | ASP.NET Framework | [Languages/DotNet.md](../03%20Languages/DotNet.md) | Yes |
| `X-Generator: WordPress` | WordPress | [CMS/WordPress.md](../05%20CMS/WordPress.md) | Yes |
| `X-Generator: Drupal` | Drupal | [CMS/Drupal.md](../05%20CMS/Drupal.md) | Yes |
| `Set-Cookie: PHPSESSID` | PHP | [Languages/PHP.md](../03%20Languages/PHP.md) | Yes |
| `Set-Cookie: JSESSIONID` | Java | [Languages/Java.md](../03%20Languages/Java.md) | Yes |
| `Set-Cookie: csrftoken` | Django | [Frameworks/Django.md](../02%20Frameworks/Django.md) | Yes |
| `Set-Cookie: _session_id` | Rails | [Frameworks/Rails.md](../02%20Frameworks/Rails.md) | Yes |
| `Set-Cookie: laravel_session` | Laravel | [Frameworks/Laravel.md](../02%20Frameworks/Laravel.md) | Yes |
| `Set-Cookie: connect.sid` | Express | [Frameworks/Express.md](../02%20Frameworks/Express.md) | Yes |
| Cookie starts with `eyJ` | JWT | [Technologies/JWT.md](../06%20Technologies/JWT.md) | Yes |
| `/graphql` responds | GraphQL | [Technologies/GraphQL.md](../../03%20API/03%20GraphQL.md) | `[PROD-RISK]` |
| `/actuator` responds | Spring Boot | [Frameworks/Spring-Boot.md](../02%20Frameworks/Spring-Boot.md) | `[PROD-NO]` |

---

## 11. OSCP Notes + Production Notes

### OSCP

> [!IMPORTANT]
> OSCP report: take screenshots of fingerprinting output (whatweb, curl -I)
> only if it directly proves the exploited vulnerability. Recon is summarized,
> not proven by screenshot.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

### Production

> [!WARNING]
> Before any active scan:
> 1. Confirm scope in writing (which IPs, which domains, which excluded paths).
> 2. Confirm rate limits (default: 1 req/s unless agreed).
> 3. Confirm User-Agent (default vs client-provided).
> 4. Note start time + source IP for the report.
>
> If a WAF blocks you, STOP. Do not bypass. Report and ask for approval.

---

## 12. Cheatsheet

One-page commands grouped by production safety.

### Production-safe (no alerts expected)

```bash
dig +short target.com
whois target.com
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u
curl -sI http://target
whatweb -a 1 http://target
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
curl -sI http://target/favicon.ico
```

### Production with rate limiting

```bash
nmap -sV -T2 --max-rate 10 -p 80,443 --script http-title,http-headers target
httpx -u http://target -title -tech-detect -status-code -rate-limit 10
ffuf -u http://target/FUZZ -w wordlist.txt -rate 10 -t 5
```

### Lab only (aggressive)

```bash
whatweb -a 3 http://target
nikto -h http://target
nmap -sV -T4 -p- --script http-title,http-headers,http-enum target
```

---

## 13. References

- WhatWeb - https://github.com/urbanadventurer/WhatWeb
- httpx - https://github.com/projectdiscovery/httpx
- Shodan favicon hash - https://help.shodan.io/mastery/favicon-hash
- crt.sh - https://crt.sh/
- NVD - https://nvd.nist.gov/
- MITRE CVE - https://cve.mitre.org/
- PayloadsAllTheThings - https://github.com/swisskyrepo/PayloadsAllTheThings

> See also: [WAF-Detection.md](./WAF-Detection.md), [VHosts-Subdomains.md](./VHosts-Subdomains.md), [Ports-Services.md](./Ports-Services.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-10.*
