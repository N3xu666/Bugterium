# OSINT

Open-source intelligence reference: how to collect, verify, and analyze
publicly available information about people, organizations, and infrastructure,
and how defenders limit what can be discovered about them.

This category is written in the **two-track** format (Offensive / Defensive),
with an additional section `## Pentest and Red Team Application` in every file
that ties the technique to authorized offensive engagements.

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.<br>
> See [SECURITY.md](../SECURITY.md) for the full policy.
## Scope

- OSINT methodology: collection planning, source evaluation, verification.
- People search: identity resolution, social media, public records.
- Infrastructure OSINT: domains, certificates, DNS, cloud assets, Shodan/Censys.
- Social media and content: platform-specific collection, geolocation, media forensics.
- Corporate and business OSINT: corporate registries, filings, employee mapping, supply chain.

## Subcategories

| # | Subcategory | Files | Focus |
|---|-------------|-------|-------|
| 01 | [OSINT Methodology](./01%20OSINT%20Methodology/) | 4 | Collection planning, source evaluation, verification |
| 02 | [People Search](./02%20People%20Search/) | 4 | Identity resolution, social media, public records |
| 03 | [Infrastructure OSINT](./03%20Infrastructure%20OSINT/) | 4 | Domains, certificates, DNS, cloud assets, Shodan/Censys |
| 04 | [Social Media and Content](./04%20Social%20Media%20and%20Content/) | 4 | Platform-specific collection, geolocation, media forensics |
| 05 | [Corporate and Business OSINT](./05%20Corporate%20and%20Business%20OSINT/) | 5 | Corporate registries, filings, employee mapping, supply chain |

## Format

Files in this category follow the two-track skeleton plus one
OSINT-specific section:

```text
## 1. Overview
## 2. Reconnaissance / Collection
## 3. Common Attack Vectors
## 4. Exploitation Recipes
## 5. Post-Exploitation
## 6. Preventive Controls
## 7. Detection Controls
## 8. Verification
## 9. Pentest and Red Team Application
## 10. Legal and Ethical Notes
## 11. Production Notes
## 12. References
```

The Offensive track covers sections 2-5 (collection through
post-exploitation). The Defensive track covers sections 6-8
(preventive controls, detection, verification). Section 9 ties the
technique to authorized offensive engagements. Section 10 covers
jurisdiction, consent, and legal boundaries - OSCP does not cover
OSINT, so the exam-notes section is replaced by legal notes.

## Related Categories

- [APPLICATIONS](../APPLICATIONS/) - web application security and API testing.
- [INFRASTRUCTURE](../INFRASTRUCTURE/) - infrastructure attack and defense.
- [CLOUD](../CLOUD/) - cloud security and asset discovery.
- [INFORMATION_SECURITY](../INFORMATION_SECURITY/) - governance, risk, compliance.
- CTI (planned) - threat intelligence that consumes OSINT sources.

## References

- OSINT Framework - https://osintframework.com/
- Bellingcat's Online Investigation Toolkit - https://bellingcat.gitbook.io/toolkit
- SANS OSINT Summit resources - https://www.sans.org/cyber-security-training/
- NIST SP 800-53 (Privacy controls) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
