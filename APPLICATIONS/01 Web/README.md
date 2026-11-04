# Web Application Security Reference

Web application security reference organized by stack: frameworks, languages, servers, CMS, technologies, databases, vulnerabilities, and OWASP Top 10. Covers detection, enumeration, exploitation patterns, and known CVEs (with NVD/MITRE links). Commands are universal; English only.

> [!CAUTION]
> Authorized use only. All techniques here are for OSCP labs, Hack The Box, and explicitly authorized penetration tests.<br>
> See [../../SECURITY.md](../../SECURITY.md).

---

## Table of Contents

| # | Section | Description |
|---|---------|-------------|
| - | [Decision Tree](#decision-tree) | Choose the right path based on the exposed service |
| - | [Quick Reference](#quick-reference) | Common ports, tools, and one-liners |
| 1 | [Recon](./01%20Recon/) | Subdomain enumeration, port scanning, web tech fingerprinting |
| 2 | [Frameworks](./02%20Frameworks/) | Spring, Django, Rails, Laravel, Express, and their CVEs |
| 3 | [Languages](./03%20Languages/) | PHP, Python, Java, .NET, Node.js, Ruby specific vulnerabilities |
| 4 | [Servers](./04%20Servers/) | Apache, Nginx, IIS, Tomcat configuration and CVEs |
| 5 | [CMS](./05%20CMS/) | WordPress, Joomla, Drupal, and plugin vulnerabilities |
| 6 | [Technologies](./06%20Technologies/) | REST, GraphQL, WebSocket, JWT, OAuth, SAML |
| 7 | [Databases](./07%20Databases/) | SQL injection, NoSQL injection, Redis, Elasticsearch |
| 8 | [Vulnerabilities](./08%20Vulnerabilities/) | OWASP Top 10 deep dives (XSS, SSRF, IDOR, etc.) |
| 9 | [OWASP Top 10](./09%20OWASP%20Top%2010/) | 2021 categories, mapping to files |
| - | [Workflow](#workflow) | How to use this reference in a pentest |

---

## Decision Tree

When you find a web service, follow this tree.

```text
nmap shows 80 / 443 / 8080 / 8443 / 8000 / 3000 / 5000 / 9000 / etc.
    |
    +-- whatweb -a 3 http://target
    +-- curl -sI http://target
    +-- nmap -sV -p <port> --script http-title,http-headers,http-methods target
    |
    v
What do we see?
    |
    +-- "WordPress"        --> 05 CMS/WordPress.md
    +-- "Joomla"           --> 05 CMS/Joomla.md
    +-- "Drupal"           --> 05 CMS/Drupal.md
    +-- "Magento"          --> 05 CMS/Magento.md
    +-- "phpMyAdmin"       --> 05 CMS/phpMyAdmin.md
    +-- "Adminer"          --> 05 CMS/Adminer.md
    |
    +-- "Django"           --> 02 Frameworks/Django.md
    +-- "Flask"            --> 02 Frameworks/Flask.md
    +-- "Rails"            --> 02 Frameworks/Rails.md
    +-- "Spring"           --> 02 Frameworks/Spring-Boot.md
    +-- "Laravel"          --> 02 Frameworks/Laravel.md
    +-- "Express"          --> 02 Frameworks/Express.md
    +-- "ASP.NET"          --> 02 Frameworks/ASP.NET.md
    +-- "Next.js"          --> 02 Frameworks/Next.js.md
    |
    +-- "X-Powered-By: PHP"    --> 03 Languages/PHP.md
    +-- "X-Powered-By: Python" --> 03 Languages/Python.md
    +-- "X-Powered-By: Express"--> 03 Languages/NodeJS.md
    +-- "X-Powered-By: ASP.NET"--> 03 Languages/DotNet.md
    +-- "X-Powered-By: Java"   --> 03 Languages/Java.md
    |
    +-- "Server: Apache"    --> 04 Servers/Apache.md
    +-- "Server: nginx"     --> 04 Servers/Nginx.md
    +-- "Server: Microsoft-IIS" --> 04 Servers/IIS.md
    +-- "Server: Apache-Coyote" --> 04 Servers/Tomcat.md
    +-- "Server: Jetty"     --> 04 Servers/Jetty.md
    |
    +-- "JWT" in cookies         --> 06 Technologies/JWT.md
    +-- "OAuth" / "authorize"    --> 06 Technologies/OAuth.md
    +-- "/graphql" endpoint      --> 06 Technologies/GraphQL.md
    +-- Database banner visible  --> 07 Databases/README.md
    +-- SSTI signature           --> 08 Vulnerabilities/SSTI.md
    |
    +-- Nothing obvious         --> 01 Recon/Fingerprinting.md
                                 + 01 Recon/VHosts-Subdomains.md
```

---

## Quick Reference

### Common HTTP Ports

| Port | Common Use |
|------|------------|
| 80 | HTTP |
| 443 | HTTPS |
| 8000 | Django dev, Python http.server |
| 8080 | Tomcat, Jenkins, generic HTTP alt |
| 8443 | HTTPS alt (Tomcat, JBoss) |
| 8888 | Jupyter, generic alt |
| 3000 | Node.js (Express, Next.js) |
| 5000 | Flask, .NET Kestrel |
| 9000 | PHP-FPM, Portainer |
| 9090 | Cockpit, Prometheus |

### Fingerprinting One-Liners

```bash
# Headers + status
curl -sI http://target

# Full fingerprint (headers, tech, CMS, analytics)
whatweb -a 3 http://target

# Nmap service + HTTP scripts
nmap -sV -p 80,443,8080,8443 --script http-title,http-headers,http-methods,http-enum target

# Tech detect via favicon hash
curl -s http://target/favicon.ico | md5sum

# robots.txt + sitemap
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
```

### Common Tools

| Tool | Purpose |
|------|---------|
| `whatweb` | Tech fingerprinting |
| `nikto` | Web server scanner |
| `gobuster dir` | Directory brute-force |
| `feroxbuster` | Recursive content discovery |
| `ffuf` | Fuzzing (dir, vhost, params) |
| `wfuzz` | Fuzzing (alternative) |
| `sqlmap` | SQL injection |
| `wpscan` | WordPress scanner |
| `joomscan` | Joomla scanner |
| `droopescan` | Drupal / SilverStripe scanner |
| `nuclei` | Template-based scanner |
| `burpsuite` | Manual proxy + scanner |
| `jwt_tool` | JWT manipulation |

---

## 01 Recon

Fingerprinting, vhosts, subdomains, port-to-service mapping.

| File | Purpose |
|------|---------|
| [Fingerprinting.md](./01%20Recon/Fingerprinting.md) | Identify the stack without a browser |
| [VHosts-Subdomains.md](./01%20Recon/VHosts-Subdomains.md) | Virtual host and subdomain enumeration |
| [Ports-Services.md](./01%20Recon/Ports-Services.md) | Common HTTP ports and what they mean |

---

## 02 Frameworks

Framework-specific detection, enumeration, exploitation.

| File | Language |
|------|----------|
| [Django.md](./02%20Frameworks/Django.md) | Python |
| [Flask.md](./02%20Frameworks/Flask.md) | Python |
| [Rails.md](./02%20Frameworks/Rails.md) | Ruby |
| [Spring-Boot.md](./02%20Frameworks/Spring-Boot.md) | Java |
| [Laravel.md](./02%20Frameworks/Laravel.md) | PHP |
| [Express.md](./02%20Frameworks/Express.md) | Node.js |
| [ASP.NET.md](./02%20Frameworks/ASP.NET.md) | .NET |
| [Next.js.md](./02%20Frameworks/Next.js.md) | Node.js |

---

## 03 Languages

Language-specific vulnerabilities and quirks.

| File | Focus |
|------|-------|
| [PHP.md](./03%20Languages/PHP.md) | LFI, RFI, deserialization, type juggling |
| [Python.md](./03%20Languages/Python.md) | SSTI, pickle, deserialization |
| [NodeJS.md](./03%20Languages/NodeJS.md) | Prototype pollution, SSTI, deserialization |
| [Java.md](./03%20Languages/Java.md) | Deserialization, EL injection, JNDI |
| [DotNet.md](./03%20Languages/DotNet.md) | ViewState, deserialization |
| [Ruby.md](./03%20Languages/Ruby.md) | ERB SSTI, Marshal |
| [Go.md](./03%20Languages/Go.md) | template injection |

---

## 04 Servers

Web servers and application servers.

| File | Notes |
|------|-------|
| [Apache.md](./04%20Servers/Apache.md) | .htaccess, mod_cgi, path traversal |
| [Nginx.md](./04%20Servers/Nginx.md) | alias traversal, off-by-slash |
| [IIS.md](./04%20Servers/IIS.md) | shortname, WebDAV, ASPX |
| [Tomcat.md](./04%20Servers/Tomcat.md) | manager, WAR deploy, CVEs |
| [Jetty.md](./04%20Servers/Jetty.md) | CVE-2021-28164, webapps |

---

## 05 CMS

Content management systems and admin panels.

| File | Common CVEs |
|------|-------------|
| [WordPress.md](./05%20CMS/WordPress.md) | plugins, themes, xmlrpc, wp-json |
| [Joomla.md](./05%20CMS/Joomla.md) | extensions, com_* components |
| [Drupal.md](./05%20CMS/Drupal.md) | Drupalgeddon 1/2/3 |
| [Magento.md](./05%20CMS/Magento.md) | SQLi, deserialization |
| [PrestaShop.md](./05%20CMS/PrestaShop.md) | SQLi, file upload |
| [phpMyAdmin.md](./05%20CMS/phpMyAdmin.md) | LFI, SQLi, auth bypass |
| [Adminer.md](./05%20CMS/Adminer.md) | SSRF, file read |

---

## 06 Technologies

Protocols, auth, and cross-cutting technologies.

| File | Focus |
|------|-------|
| [JWT.md](./06%20Technologies/JWT.md) | alg=none, kid injection, JWK, weak secret |
| [OAuth.md](./06%20Technologies/OAuth.md) | redirect_uri, state, PKCE |
| [GraphQL.md](../03%20API/03%20GraphQL.md) | introspection, batching, IDOR |
| [REST.md](../03%20API/02%20REST.md) | mass assignment, IDOR, verb tampering |
| [WebSocket.md](../03%20API/05%20WebSocket.md) | CSWSH, injection |
| [SSTI.md](./08%20Vulnerabilities/SSTI.md) | Jinja2, Twig, Freemarker, ERB |
| [Deserialization.md](./08%20Vulnerabilities/Deserialization.md) | PHP, Java, Python, .NET, Ruby |

## 07 Databases

Database engines, detection, and per-DB exploitation.

| File | Engine |
|------|--------|
| [README.md](./07%20Databases/README.md) | Detection, enumeration, common misconfigurations |
| [MySQL.md](./07%20Databases/MySQL.md) | MySQL / MariaDB |
| [PostgreSQL.md](./07%20Databases/PostgreSQL.md) | PostgreSQL |
| [MSSQL.md](./07%20Databases/MSSQL.md) | Microsoft SQL Server |
| [MongoDB.md](./07%20Databases/MongoDB.md) | MongoDB |
| [Redis.md](./07%20Databases/Redis.md) | Redis |
| [SQLite.md](./07%20Databases/SQLite.md) | SQLite |
| [Oracle.md](./07%20Databases/Oracle.md) | Oracle DB |

---

## 08 Vulnerabilities

Vulnerability classes with exploitation recipes.

| File | Notes |
|------|-------|
| [SQLi.md](./08%20Vulnerabilities/SQLi.md) | Union, blind, time-based, error-based |
| [XSS.md](./08%20Vulnerabilities/XSS.md) | Reflected, stored, DOM, CSP bypass |
| [SSRF.md](./08%20Vulnerabilities/SSRF.md) | Cloud metadata, gopher, file:// |
| [LFI-RFI.md](./08%20Vulnerabilities/LFI-RFI.md) | Wrappers, log poisoning |
| [XXE.md](./08%20Vulnerabilities/XXE.md) | File read, SSRF, blind OOB |
| [IDOR.md](./08%20Vulnerabilities/IDOR.md) | Horizontal / vertical escalation |
| [File-Upload.md](./08%20Vulnerabilities/File-Upload.md) | Bypass, polyglot, magic bytes |
| [Command-Injection.md](./08%20Vulnerabilities/Command-Injection.md) | Blind, OOB, WAF bypass |
| [SSTI.md](./08%20Vulnerabilities/SSTI.md) | Server-side template injection |
| [Deserialization.md](./08%20Vulnerabilities/Deserialization.md) | Multi-language |
| [CSRF.md](./08%20Vulnerabilities/CSRF.md) | Token bypass, SameSite |
| [Open-Redirect.md](./08%20Vulnerabilities/Open-Redirect.md) | Phishing, OAuth chain |

---

## 09 OWASP Top 10

Maps the OWASP Top 10:2021 categories to the files above.
Includes four dedicated two-track files (A01, A04, A06, A09 - each with
Pentest and AppSec sections) and a comparison with the 2025 revision.

| File | Notes |
|------|-------|
| [README.md](./09%20OWASP%20Top%2010/README.md) | Coverage map: 2021 categories -> existing files |
| [2021-vs-2025.md](./09%20OWASP%20Top%2010/2021-vs-2025.md) | What changed between revisions |
| [A01-Broken-Access-Control.md](./09%20OWASP%20Top%2010/A01-Broken-Access-Control.md) | A01: Broken Access Control (pentest + AppSec) |
| [A04-Insecure-Design.md](./09%20OWASP%20Top%2010/A04-Insecure-Design.md) | A04: Insecure Design (pentest + AppSec) |
| [A06-Vulnerable-Components.md](./09%20OWASP%20Top%2010/A06-Vulnerable-Components.md) | A06: Vulnerable Components (pentest + AppSec + supply chain) |
| [A09-Logging-Failures.md](./09%20OWASP%20Top%2010/A09-Logging-Failures.md) | A09: Logging and Monitoring Failures (pentest + AppSec) |

---

## Workflow

Standard web-testing workflow. Adjust per target profile
(lab vs production - see [../METHODOLOGY.md](../../METHODOLOGY.md)).

1. **Fingerprint** - `whatweb`, `curl -I`, nmap HTTP scripts.
2. **Enumerate** - directories (`feroxbuster`), files, vhosts (`ffuf`).
3. **Identify stack** - framework, language, server, CMS, DB.
4. **Look up CVEs** - NVD / MITRE for the exact version.
5. **Test known vulns** - SQLi, XSS, SSRF, LFI, upload, etc.
6. **Chain** - combine findings into a foothold / privesc.
7. **Document** - screenshots for OSCP, expected output in walkthroughs.

### OSCP Notes

> [!IMPORTANT]
> For OSCP, every proof step (foothold, privilege escalation) needs a
> screenshot with command, output, and timestamp. See
> [../methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md).

---

## Related Sections

- [../CHEATSHEET.md](../../CHEATSHEET.md) - general pentest commands.
- [../METHODOLOGY.md](../../METHODOLOGY.md) - engagement workflow.
- [../methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md) - exam reporting.
- [../WRITEUPS/](../../WRITEUPS/) - HTB walkthroughs using these techniques.

---

*Last updated: 2026-10-10. Part of Bugterium. English only by design.*
