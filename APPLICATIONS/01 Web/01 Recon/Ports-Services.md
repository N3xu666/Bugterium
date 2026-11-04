# Ports & Services (HTTP)

> Common HTTP ports, what services run on them, and where to go next.
> Use this to narrow down the stack before sending a single HTTP request.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Common HTTP Ports](#3-common-http-ports)
- [4. Common Database Ports](#4-common-database-ports)
- [5. Fingerprinting via nmap](#5-fingerprinting-via-nmap)
- [6. TLS/SNI Differences](#6-tlssni-differences)
- [7. Non-HTTP Ports with Web UIs](#7-non-http-ports-with-web-uis)
- [8. Dev Servers](#8-dev-servers)
- [9. Decision Tree](#9-decision-tree)
- [10. OSCP Notes](#10-oscp-notes)
- [11. Cheatsheet](#11-cheatsheet)
- [12. References](#12-references)

---

## 1. Overview

The port number narrows down the likely stack before you send a request.

**Rules:**

- 80 / 443 = standard web, expect anything.
- 8080 / 8443 = "admin" territory: Tomcat, Jenkins, JBoss, generic alt HTTP.
- 8000 / 5000 / 3000 = development servers, often debug-enabled.
- 8888 / 9090 / 9200 / 15672 = non-HTTP tools with web UIs and weak defaults.
- Database ports (3306, 5432, ...) = direct DB access, move to Databases.md.

In a lab, default ports are usually open. In production, they may be filtered
behind a WAF, a reverse proxy, or a firewall.

---

## 2. Scope & OPSEC

### 2.1 Port scan risk

| Target | Tag | Notes |
|--------|-----|-------|
| Lab (OSCP, HTB, PG) | `[LAB]` | `nmap -T4 -p-` fine |
| Production | `[PROD-RISK]` | IDS/IPS alert on full port scan |

### 2.2 Rate limiting

| nmap mode | Lab | Production |
|-----------|-----|------------|
| Full port scan | `-T4 -p-` | `-T2 --max-rate 100 -p-` (may take hours) |
| Service detection | `-sV` default | `-sV -T2 --max-rate 50` |
| NSE scripts | default | `--script-timeout 30s -T2` |

In production, scan known ports first (`nmap -p 80,443,8080,8443 target`),
only do a full scan with client approval.

### 2.3 What NOT to do (production)

- Do NOT `nmap -T4 -p-` against a public target without approval.
- Do NOT run `--script http-enum` (directory brute-force) in production.
- Do NOT scan database ports from outside the scope network.

---

## 3. Common HTTP Ports

| Port | Common service | Notes |
|------|----------------|-------|
| 80 | HTTP | Default web |
| 443 | HTTPS | TLS; SNI-based vhosts |
| 3000 | Grafana, Node.js (Express, Next.js) | Dev servers |
| 5000 | Flask dev, .NET Kestrel | Debug often enabled |
| 5601 | Kibana | Often behind Elasticsearch |
| 7001 | WebLogic (Oracle) | CVE magnet, admin console |
| 8000 | Django dev, Python `http.server` | Debug often enabled |
| 8008 | Google Cloud endpoints, alt HTTP | |
| 8080 | Tomcat, Jenkins, generic alt HTTP | Common "admin" port |
| 8081 | Nexus, alt Node | |
| 8161 | ActiveMQ | Default creds `admin:admin` |
| 8443 | HTTPS alt (Tomcat, JBoss, Jenkins) | |
| 8888 | Jupyter Notebook | Often no auth |
| 9000 | PHP-FPM, Portainer, SonarQube | |
| 9090 | Cockpit, Prometheus | Both expose UI |
| 9200 | Elasticsearch | Often no auth |
| 15672 | RabbitMQ management | Default `guest:guest` |

### 3.1 Reading the banner

```bash
nmap -sV -p 80,443,8080,8443 target
```

**Expected output:**

```text
80/tcp   open  http     nginx 1.18.0
443/tcp  open  ssl/http nginx 1.18.0
8080/tcp open  http     Apache Tomcat/Coyote JSP engine 1.1
8443/tcp open  ssl/http Apache Tomcat/Coyote JSP engine 1.1
```

The `-sV` banner + `Server:` header together give you the stack.

---

## 4. Common Database Ports

Exposed database ports = direct access target. Full exploitation in
[../07 Databases.md](../07%20Databases/README.md).

| Port | Database | Notes |
|------|----------|-------|
| 1433 | MSSQL | Often with `sa` default |
| 1521 | Oracle DB | TNS listener |
| 2181 | Zookeeper | Metadata for Kafka, etc. |
| 3306 | MySQL / MariaDB | Often `root` without password |
| 5432 | PostgreSQL | Weak creds common |
| 5984 | CouchDB | Often no auth, admin party |
| 6379 | Redis | Often no auth, RCE via module load |
| 11211 | Memcached | Info leak, no auth |
| 27017 | MongoDB | Often no auth |

**Quick check from outside:**

```bash
nmap -sV -p 3306,5432,1433,6379,27017 target
```

**Expected output:**

```text
3306/tcp  open  mysql    MySQL 8.0.28
6379/tcp  open  redis    Redis key-value store 6.2.6
27017/tcp open  mongodb  MongoDB 5.0.5
```

---

## 5. Fingerprinting via nmap

### 5.1 Service detection

```bash
nmap -sV -p 80,443,8080,8443 target
```

### 5.2 HTTP scripts

```bash
nmap -sV -p 80,443 --script http-title,http-headers,http-methods target
```

**Expected output:**

```text
80/tcp open  http    nginx 1.18.0
|_http-title: Welcome to ExampleApp
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0
```

### 5.3 Directory enumeration (LAB only)

```bash
nmap -p 80 --script http-enum target
```

Runs a built-in directory brute-force. Noisy. `[LAB]` only.

### 5.4 TLS cipher enumeration

```bash
nmap -p 443 --script ssl-enum-ciphers target
```

**Expected output:**

```text
| ssl-enum-ciphers:
|   TLSv1.2:
|     ciphers:
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
|     least strength: A
```

Reveals the TLS stack, useful for detecting old servers or picking a bypass.

### 5.5 Vhost brute (LAB only)

```bash
nmap -p 80 --script http-vhosts --script-args http-vhosts.file=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt target
```

Same idea as `gobuster vhost` but through nmap. See
[VHosts-Subdomains.md](./VHosts-Subdomains.md).

---

## 6. TLS/SNI Differences

Port 443 (HTTPS) can serve different vhosts than port 80 (HTTP).
Even on the same IP, port 443 may route by TLS SNI.

### 6.1 Extract the certificate

```bash
echo | openssl s_client -connect target:443 -servername target.com 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

**Expected output:**

```text
subject=CN = target.com
issuer=C = US, O = Let's Encrypt, CN = R3
notBefore=Jan  1 00:00:00 2026 GMT
notAfter=Apr  1 00:00:00 2026 GMT
X509v3 Subject Alternative Name:
    DNS:target.com, DNS:www.target.com, DNS:admin.target.com
```

SAN entries reveal subdomains - cross-reference with `crt.sh`.

### 6.2 Check what a specific SNI returns

```bash
curl -sI https://target --resolve admin.target.com:443:10.10.10.10
curl -sI https://target -H "Host: admin.target.com" --insecure
```

### 6.3 Test alternate HTTPS port

```bash
curl -sI https://target:8443 --insecure
echo | openssl s_client -connect target:8443 2>/dev/null | openssl x509 -noout -subject
```

Sometimes 8443 exposes a completely different application.

---

## 7. Non-HTTP Ports with Web UIs

Some services are not HTTP but expose a web UI. Reaching them with a browser
or `curl` often reveals default creds or unauthenticated access.

| Port | Service | Web UI | Exploitation reference |
|------|---------|--------|------------------------|
| 7001 | Oracle WebLogic | `http://target:7001/console` | See `08 Vulnerabilities/Deserialization.md` |
| 8161 | ActiveMQ | `http://target:8161/admin` | Default `admin:admin` -> CVE-2016-3088 (fileserver RCE) |
| 8888 | Jupyter Notebook | `http://target:8888` | No auth -> RCE via notebook (see `08 Vulnerabilities/Command-Injection.md` §Jupyter) |
| 9000 | Portainer | `http://target:9000` | Admin panel; docker escape |
| 9090 | Cockpit | `https://target:9090` | Linux systemd via web UI |
| 9090 | Prometheus | `http://target:9090` | Info leak via `/metrics`, `/api/v1/targets` |
| 9200 | Elasticsearch | `http://target:9200` | No auth -> data leak, RCE via scripting (see `06 Technologies/Databases.md`) |
| 15672 | RabbitMQ management | `http://target:15672` | Default `guest:guest` -> RCE via definitions |
| 5601 | Kibana | `http://target:5601` | CVE-2019-7609 (RCE via Timelion) |

Each of these is worth a `curl -sI` probe as soon as nmap finds it open.

---

## 8. Dev Servers

Development servers run in debug mode by default. Debug mode means:

- Stack traces in error pages.
- Sometimes RCE (Flask Werkzeug console, Django debug).
- Hot-reload enabled, files readable.

| Port | Stack | Signal |
|------|-------|--------|
| 3000 | Node.js (Express, Next.js, React dev) | `X-Powered-By: Express` |
| 5000 | Flask, .NET Kestrel | Flask: `Werkzeug/<version>` |
| 8000 | Django, `python -m http.server` | Django: `Server: WSGIServer/0.2 CPython/...` |
| 8080 | Alt Tomcat or Jenkins | `Server: Apache-Coyote` |

Probe for debug pages:

```bash
curl -s http://target:8000/does-not-exist
curl -s http://target:5000/console
```

See [Fingerprinting.md](./Fingerprinting.md) §7 for stack-specific debug pages.

---

## 9. Decision Tree

| Port | Likely stack | Next file |
|------|--------------|-----------|
| 80, 443 | Anything | [Fingerprinting.md](./Fingerprinting.md) |
| 3000 | Node.js, Grafana, Next.js | [../02 Frameworks/Express.md](../02%20Frameworks/Express.md) |
| 5000 | Flask, .NET Kestrel | [../02 Frameworks/Flask.md](../02%20Frameworks/Flask.md) |
| 5601 | Kibana | [08 Vulnerabilities/](../08%20Vulnerabilities/) (CVE-2019-7609) |
| 7001 | WebLogic | [../03 Languages/Java.md](../03%20Languages/Java.md) (deserialization) |
| 8000 | Django, Python dev server | [../02 Frameworks/Django.md](../02%20Frameworks/Django.md) |
| 8080 | Tomcat, Jenkins | [../04 Servers/Tomcat.md](../04%20Servers/Tomcat.md) |
| 8161 | ActiveMQ | [08 Vulnerabilities/](../08%20Vulnerabilities/) (CVE-2016-3088) |
| 8443 | Tomcat HTTPS alt | [../04 Servers/Tomcat.md](../04%20Servers/Tomcat.md) |
| 8888 | Jupyter | [Command-Injection.md](../08%20Vulnerabilities/Command-Injection.md) - Jupyter section |
| 9000 | Portainer, PHP-FPM | [../03 Languages/PHP.md](../03%20Languages/PHP.md) |
| 9090 | Cockpit, Prometheus | Info leak (no dedicated file yet) |
| 9200 | Elasticsearch | [../07 Databases.md](../07%20Databases/README.md) |
| 15672 | RabbitMQ management | [08 Vulnerabilities/](../08%20Vulnerabilities/) (RCE via definitions) |
| 3306 / 5432 / 1433 / 27017 / 6379 | MySQL / PostgreSQL / MSSQL / MongoDB / Redis | [../07 Databases.md](../07%20Databases/README.md) |

---

## 10. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the nmap `-sV` output that reveals the service version you
>   later exploited.
> - Screenshot the specific port + banner only if it is part of the foothold
>   or privesc chain.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 11. Cheatsheet

### Recon

```bash
# Quick port check
nmap -p 80,443,8080,8443,8000,3000,5000 target

# Full port scan (LAB)
nmap -sV -T4 -p- target

# Full port scan (PROD - slow)
nmap -sV -T2 --max-rate 100 -p- target

# HTTP scripts
nmap -sV -p 80,443 --script http-title,http-headers,http-methods target
```

### TLS / SNI

```bash
echo | openssl s_client -connect target:443 -servername target.com 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName
curl -sI https://target --resolve admin.target.com:443:10.10.10.10
curl -sI https://target:8443 --insecure
```

### Non-HTTP web UIs

```bash
curl -s http://target:9200/
curl -s http://target:15672/
curl -s http://target:8161/admin/
curl -s http://target:8888/
```

---

## 12. References

- nmap NSE - https://nmap.org/nsedoc/
- SecLists - https://github.com/danielmiessler/SecLists
- HackTricks - 8080 Pentesting - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web
- PayloadsAllTheThings - https://github.com/swisskyrepo/PayloadsAllTheThings

> See also: [Fingerprinting.md](./Fingerprinting.md), [WAF-Detection.md](./WAF-Detection.md), [VHosts-Subdomains.md](./VHosts-Subdomains.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-10.*
