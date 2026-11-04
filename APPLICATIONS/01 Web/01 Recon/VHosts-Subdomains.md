# VHosts & Subdomains

> Enumerate virtual hosts and subdomains to find admin panels, staging
> environments, and forgotten services that share the same infrastructure.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Passive Enumeration](#3-passive-enumeration)
- [4. Active Subdomain Enumeration](#4-active-subdomain-enumeration)
- [5. VHost Fuzzing](#5-vhost-fuzzing)
- [6. /etc/hosts Setup](#6-etchosts-setup)
- [7. Wordlists](#7-wordlists)
- [8. What to Do With Findings](#8-what-to-do-with-findings)
- [9. Common Mistakes](#9-common-mistakes)
- [10. OSCP Notes](#10-oscp-notes)
- [11. Cheatsheet](#11-cheatsheet)
- [12. References](#12-references)

---

## 1. Overview

Three different things that are often confused:

| Concept | What it means | How to find |
|---------|---------------|-------------|
| **Subdomain** | Different DNS record (`admin.example.com`) | DNS enumeration |
| **VHost** | Same IP, routed by `Host:` header (`admin` on same IP) | HTTP fuzzing with `Host:` header |
| **Virtual directory** | Path on the same vhost (`/admin/`) | Directory brute-force |

**Why enumerate:**

- Development / staging environments are often less protected.
- Admin panels hide on separate subdomains / vhosts.
- Forgotten services (test., old., backup.) expose old code and creds.
- The same IP can serve 5-20 different sites via SNI or Host header.

**Rule:** a subdomain enum without vhost fuzzing misses half the targets.
Do both.

---

## 2. Scope & OPSEC

### 2.1 Passive vs active

| Method | Traffic to target | Tag |
|--------|-------------------|-----|
| Certificate Transparency, DNS, WHOIS, Shodan | None (third parties) | `[PROD]` |
| DNS brute-force (gobuster, ffuf dns) | DNS queries only | `[PROD]` |
| VHost fuzzing (HTTP requests) | Direct HTTP | `[PROD-RISK]` |

### 2.2 Rate limiting

| Tool | Lab | Production |
|------|-----|------------|
| `gobuster dns` | default | `--delay 50ms -t 20` |
| `ffuf` (DNS) | default | `-rate 20 -t 10` |
| `ffuf` (vhost) | default | `-rate 10 -t 5` |
| `gobuster vhost` | default | `--delay 100ms -t 5` |
| `amass enum` (active) | default | `-timeout 5 -max-dns-queries 20` |
| `dnsx` | default | `-rate-limit 20` |

### 2.3 Common pitfalls in production

- Do NOT brute-force at full speed in production - DNS is usually rate-limited by the provider and abuse may be reported.
- Do NOT fuzz vhosts with aggressive wordlists without approval.
- Do NOT assume subdomains are in scope. Check the scope document.

---

## 3. Passive Enumeration

No direct interaction with the target's HTTP services.

### 3.1 DNS and WHOIS

```bash
dig +short target.com
dig +short -t ANY target.com
dig +short -t NS target.com
whois target.com | grep -iE 'name server|registrar|organization'
```

### 3.2 Certificate Transparency (crt.sh)

Every TLS certificate issued for a domain is public. Subdomains leak via SANs.

```bash
# CLI
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u

# Web UI
# https://crt.sh/?q=target.com
```

**Expected output:**

```text
admin.target.com
api.target.com
staging.target.com
*.target.com
www.target.com
```

### 3.3 Google dorking

```text
site:*.target.com -www
site:*.target.com inurl:admin
site:*.target.com -inurl:www
```

### 3.4 Shodan / Censys

```text
# Shodan
ssl:target.com
hostname:target.com

# Censys
services.tls.certificates.leaf_data.names: target.com
```

### 3.5 TheHarvester

```bash
theHarvester -d target.com -b all -f report.html
```

Sources: search engines, PGP keys, LinkedIn, GitHub.

### 3.6 amass (passive)

```bash
amass enum -passive -d target.com -o subs.txt
```

### 3.7 subfinder / assetfinder

```bash
subfinder -d target.com -silent -o subs.txt
assetfinder --subs-only target.com
```

### 3.8 Merge + deduplicate

```bash
cat subs*.txt | sort -u > all-subs.txt
wc -l all-subs.txt
```

---

## 4. Active Subdomain Enumeration

DNS brute-force against common names. DNS only, no HTTP.

### 4.1 gobuster dns

```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20
gobuster dns -d target.com -w wordlist.txt --show-ips
```

**Expected output:**

```text
Found: admin.target.com
Found: api.target.com
Found: staging.target.com
```

### 4.2 ffuf (DNS)

```bash
ffuf -u http://FUZZ.target.com -w wordlist.txt -fs 0 -rate 20
```

### 4.3 dnsx

```bash
cat wordlist.txt | dnsx -d target.com -silent -a -resp
```

### 4.4 amass (active)

```bash
amass enum -active -d target.com -brute -w wordlist.txt -o subs.txt
```

### 4.5 Resolve found names

```bash
while read sub; do
    ip=$(dig +short "$sub" | head -1)
    [ -n "$ip" ] && echo "$sub -> $ip"
done < subs.txt
```

---

## 5. VHost Fuzzing

Same IP, different `Host:` header. Often the only way to find internal apps.

### 5.1 The concept

A server at 10.10.10.10 may respond to:

- `Host: target.htb` -> main site
- `Host: admin.target.htb` -> admin panel
- `Host: staging.target.htb` -> staging

None of these names need to be in public DNS.

### 5.2 Manual curl test

```bash
curl -sI http://10.10.10.10 -H "Host: admin.target.htb"
curl -sI http://10.10.10.10 -H "Host: staging.target.htb"

# Compare:
curl -sI http://10.10.10.10 -H "Host: does-not-exist" | head -1
```

If the response is identical for every Host header, vhost fuzzing will not work (or needs a different filter).

### 5.3 gobuster vhost

```bash
gobuster vhost -u http://target.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# Production: add rate limit
gobuster vhost -u http://target.htb -w wordlist.txt --append-domain --delay 100ms -t 5
```

**Expected output:**

```text
Found: admin.target.htb Status: 200 [Size: 1234]
Found: staging.target.htb Status: 302 [Size: 0]
```

### 5.4 ffuf (vhost)

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -fs 0

# Filter by response size (default page size)
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -fs 1234

# Match only 200/302
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -mc 200,302
```

### 5.5 HTTPS vhosts (SNI-based)

Some vhosts only respond on 443. Always test both.

```bash
curl -sI https://10.10.10.10 -H "Host: admin.target.htb" --insecure
ffuf -u https://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -fs 0
```

### 5.6 Filtering noise

Most vhost wordlists will return the default page for every miss. Filter by:

- `-fs <size>` - filter by response size.
- `-fl <lines>` - filter by line count.
- `-fw <words>` - filter by word count.
- `-fc <codes>` - filter out specific status codes.

First, determine the default response:

```bash
curl -sI http://10.10.10.10 -H "Host: random-string-12345"
# note status, size, and body
```

Then filter against it.

### 5.7 Alternative routing headers

Some setups route by other headers, not just `Host`.

```bash
curl -sI http://target -H "X-Forwarded-Host: admin.target.htb"
curl -sI http://target -H "X-Forwarded-For: 127.0.0.1"
curl -sI http://target -H "X-Real-IP: 127.0.0.1"
curl -sI http://target -H "X-Original-URL: /admin"
curl -sI http://target -H "X-Rewrite-URL: /admin"
```

Useful when the main site is behind a reverse proxy that does host-based routing.

---

## 6. /etc/hosts Setup

Add discovered vhosts to `/etc/hosts` so tools and browsers reach them.

**Linux / macOS:** `/etc/hosts`
**Windows:** `C:\Windows\System32\drivers\etc\hosts`

```text
# target.com vhosts
10.10.10.10  target.htb
10.10.10.10  admin.target.htb
10.10.10.10  staging.target.htb
10.10.10.10  api.target.htb
```

**Linux command:**

```bash
sudo tee -a /etc/hosts <<EOF
10.10.10.10  target.htb
10.10.10.10  admin.target.htb
EOF
```

**Verify:**

```bash
getent hosts admin.target.htb
curl -sI http://admin.target.htb
```

**Windows (PowerShell, admin):**

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "10.10.10.10 target.htb"
```

### 6.1 Wildcard DNS handling

If `anything.target.com` resolves, the target has wildcard DNS.

```bash
dig +short random-string-12345.target.com
# if it returns an IP, wildcard is active
```

**Fix:** filter out results that resolve to the wildcard IP.

```bash
WILDCARD_IP=$(dig +short random-string-12345.target.com | head -1)
while read sub; do
    ip=$(dig +short "$sub" | head -1)
    [ "$ip" != "$WILDCARD_IP" ] && [ -n "$ip" ] && echo "$sub -> $ip"
done < subs.txt
```

### 6.2 Alternative ports

Do not forget vhosts may exist on:

- 80, 443 (default)
- 8080, 8443 (alternate HTTP/HTTPS)
- 8000, 3000, 5000 (dev servers)
- 9000 (PHP-FPM, admin panels)

Run vhost fuzzing against each open port.

---

## 7. Wordlists

SecLists is the standard.

| File | Size | Use case |
|------|------|----------|
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | 5k | Fast pass |
| `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt` | 110k | Deep pass |
| `/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt` | 2M | Exhaustive (slow) |
| `/usr/share/seclists/Discovery/DNS/namelist.txt` | 10k | General |
| `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` | 220k | Vhost names from dir list |

**Custom wordlists:** build from the target

- Company name variations: `acme`, `acme-dev`, `acme-staging`, `acme-old`.
- Project names, employee names (from LinkedIn).
- Tech names: `jenkins`, `gitlab`, `grafana`, `kibana`, `nagios`.

```bash
cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
    custom-words.txt | sort -u > combined.txt
```

---

## 8. What to Do With Findings

Each discovered subdomain / vhost becomes a new target.

1. **Add to `/etc/hosts`** (see §6).
2. **Fingerprint** with `curl -sI`, `whatweb` (see [Fingerprinting.md](./Fingerprinting.md)).
3. **Scan for directories** with `ffuf`, `feroxbuster`, `gobuster dir`.
4. **Check for WAF** (see [WAF-Detection.md](./WAF-Detection.md)).
5. **Look for default creds / misconfigs** on admin panels.
6. **Compare** with the main site: sometimes a subdomain runs an older version.

---

## 9. Common Mistakes

- Not filtering wildcard DNS - thousands of false positives.
- Only running subdomain enum without vhost fuzzing (misses internal apps).
- Not checking HTTPS (443) separately from HTTP (80) - different vhosts.
- Ignoring non-standard ports (8080, 8443).
- Fuzzing with the wrong wordlist - use `--append-domain` in gobuster or set the Host header properly in ffuf.
- Forgetting to add found vhosts to `/etc/hosts` - tools won't reach them.
- Not checking response size differences - identical responses mean no vhost.

---

## 10. OSCP Notes

> [!IMPORTANT]
> OSCP report: screenshot vhost enumeration only if a discovered vhost is
> part of the exploitation path (e.g. admin panel leads to RCE).
>
> Adding entries to `/etc/hosts` is exam-standard and does not require a
> screenshot unless it directly leads to a foothold.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 11. Cheatsheet

### Passive

```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r ".[].name_value" | sort -u
theHarvester -d target.com -b all
amass enum -passive -d target.com
subfinder -d target.com -silent
```

### Active subdomain

```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 20
ffuf -u http://FUZZ.target.com -w wordlist.txt -fs 0
dnsx -d target.com -w wordlist.txt -a -resp
```

### VHost fuzzing

```bash
# Determine default response
curl -sI http://10.10.10.10 -H "Host: random-string"

# Fuzz
gobuster vhost -u http://target.htb -w wordlist.txt --append-domain
ffuf -u http://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -fs <default-size>

# HTTPS
ffuf -u https://10.10.10.10 -H "Host: FUZZ.target.htb" -w wordlist.txt -fs 0
```

### /etc/hosts

```bash
echo "10.10.10.10  admin.target.htb" | sudo tee -a /etc/hosts
```

---

## 12. References

- SecLists - https://github.com/danielmiessler/SecLists
- subfinder - https://github.com/projectdiscovery/subfinder
- dnsx - https://github.com/projectdiscovery/dnsx
- amass - https://github.com/owasp-amass/amass
- theHarvester - https://github.com/laramies/theHarvester
- crt.sh - https://crt.sh/

> See also: [Fingerprinting.md](./Fingerprinting.md), [WAF-Detection.md](./WAF-Detection.md), [Ports-Services.md](./Ports-Services.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-10.*
