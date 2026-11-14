# 03 GCP

Google Cloud Platform security reference: offensive techniques against GCP-managed services and defensive controls to detect and prevent them.

## Scope

This subcategory covers the GCP attack surface as seen by a penetration tester or red teamer, paired with the defensive view a cloud security engineer needs to detect, contain and remediate the same activity.

The two tracks are complementary, not separate documents:

- **Offensive** - reconnaissance, identity and service account abuse, storage exposure, compute-level escalation and persistence.
- **Defensive** - audit logging, detection engineering, preventive controls, IAM hardening and incident response.

Every technique is framed against a GCP primitive (IAM, Service Accounts, Cloud Storage, Compute Engine, Cloud Logging) so the reader can map the attack to the control that should have stopped it.

## Files

| # | File | Format |
|---|------|--------|
| 01 | [GCP Fundamentals](./01%20GCP%20Fundamentals.md) | done |
| 02 | [IAM and Service Account Attacks](./02%20IAM%20and%20Service%20Account%20Attacks.md) | done |
| 03 | [Cloud Storage Attacks](./03%20Cloud%20Storage%20Attacks.md) | done |
| 04 | [GCE and Compute Attacks](./04%20GCE%20and%20Compute%20Attacks.md) | done |
| 05 | [GCP Defense and Detection](./05%20GCP%20Defense%20and%20Detection.md) | done |

## Format

Each file follows the two-track skeleton: Overview, Reconnaissance and Enumeration, Common Attack Vectors, Exploitation Recipes, Post-Exploitation, Preventive Controls, Detection Controls, Verification, Cloud-Specific Considerations, Production Notes, References, plus a Certification Alignment section.

## Certification Alignment

This subcategory supports preparation for:

- Google Cloud Professional Cloud Security Engineer
- Google Cloud Associate Cloud Engineer
- Google Cloud Professional Cloud Architect
- CompTIA Security+

See [../CERTIFICATIONS.md](../CERTIFICATIONS.md) in the CLOUD category root for the full mapping across the CLOUD category.

## Related

- [01 AWS](../01%20AWS/)
- [02 Azure](../02%20Azure/)
- [04 Kubernetes-Cloud](../04%20Kubernetes-Cloud/)
- [05 Serverless](../05%20Serverless/)
- [06 IaC](../06%20IaC/)

## Authorized Use Only

> [!CAUTION]
> All techniques in this subcategory are for authorized security testing only. Testing GCP resources you do not own or have explicit written permission to assess is illegal and violates the Google Cloud Acceptable Use Policy. Use a dedicated test project or the Google Cloud free tier for practice.

## References

- Google Cloud Security Best Practices - https://cloud.google.com/security/best-practices
- Google Cloud Security Command Center - https://cloud.google.com/security-command-center
- Google Cloud IAM documentation - https://cloud.google.com/iam/docs
- MITRE ATT&CK Cloud Matrix - https://attack.mitre.org/matrices/enterprise/cloud/
