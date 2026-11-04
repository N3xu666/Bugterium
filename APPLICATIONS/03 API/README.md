# API Security Reference

API attack surface: authentication, authorization, rate limiting, gateway controls, and the protocols that carry them. This category covers the API layer separately from general web application security - the threat model is different (no browser, no session cookies by default, machine clients).

Two-track format: every file has a Pentest track (detection, payloads, exploitation recipes) and an AppSec track (risk context, root causes, preventive and detection controls, verification). See the parent README for the format.

Writeups and references in this category are written in English only. The trilingual scheme (Az/En/Ru) applies to WRITEUPS only.

---

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.<br>
> See [../../SECURITY.md](../../SECURITY.md) for the full policy.
## Contents

| # | File | Focus |
|---|------|-------|
| 01 | [OWASP API Top 10](./01%20OWASP-API-Top-10.md) | 2023 categories, mapping to files |
| 02 | [REST](./02%20REST.md) | REST endpoints, IDOR, mass assignment, method tampering |
| 03 | [GraphQL](./03%20GraphQL.md) | Introspection, batching, depth attacks, injection |
| 04 | [gRPC](./04%20gRPC.md) | Protobuf, reflection, auth, streaming |
| 05 | [WebSocket](./05%20WebSocket.md) | Handshake auth, CSWSH, message injection |
| 06 | [SOAP](./06%20SOAP.md) | WSDL enumeration, XXE, WS-Security |
| 07 | [Authentication](./07%20Authentication.md) | JWT, OAuth2, API keys, mTLS |
| 08 | [Rate-Limiting](./08%20Rate-Limiting.md) | Bypass techniques, distributed brute force |
| 09 | [API-Gateway](./09%20API-Gateway.md) | Kong, APIGW, NGINX, WAF bypass |

---

## Relationship to 01 Web

The `01 Web/` category covers the browser-facing layer: HTML forms, cookies, CSRF, XSS, CMS, servers, frameworks. `03 API/` covers the machine-facing layer: no browser, tokens instead of cookies, JSON/Protobuf instead of HTML.

## Related Sections

- [../01 Web/](../01%20Web/) - browser-facing web application security.
- [../02 Mobile/](../02%20Mobile/) - mobile client security (Android, iOS).
- [../../CHEATSHEET.md](../../CHEATSHEET.md) - general pentest commands.
- [../../METHODOLOGY.md](../../METHODOLOGY.md) - engagement workflow.
- [../../methodology/OSCP-Reporting.md](../../methodology/OSCP-Reporting.md) - exam reporting.

---

*Last updated: 2026-10-24. Part of Bugterium. English only by design.*

Overlap exists in the underlying primitives (injection, authn, authz) but the detection and exploitation techniques are different enough to warrant a separate track. Cross-references point to `01 Web/` where the primitive is the same.

---

## OSCP Relevance

For OSCP, the API layer rarely appears as a standalone target. It appears as:

- A REST endpoint on a web app (IDOR for another user's data).
- A GraphQL endpoint exposing a mutation that bypasses the UI.
- A WebSocket connection with no origin check (CSWSH -> admin action).

The exploitation recipes in these files are written to be usable in a lab environment where the target is a live API, not just a theory read.

---

## References

- OWASP API Security Top 10:2023 - https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP Web Security Testing Guide - https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy (API testing) - https://portswigger.net/web-security/api-testing
- OWASP Cheat Sheet Series - https://cheatsheetseries.owasp.org/