# VIRTUALIZATION - Certification Alignment

The virtualization and container security subcategories map to the following certification objectives. The mapping is a study aid, not an official certification guide. Always check the current exam objectives published by the certification body.

## Core Certifications

| Certification | Relevant Domains |
|---------------|------------------|
| CompTIA Security+ (SY0-701) | Domain 3 (Security Architecture and Design) - virtualization, containers, cloud. Domain 4 (Security Operations) - container security, hardening. |
| CompTIA CySA+ (CS0-003) | Domain 1 (Security Operations) - container and virtualization telemetry. Domain 2 (Vulnerability Management) - hypervisor and container CVEs. |
| CISSP | Domain 3 (Security Architecture and Engineering) - virtualization, isolation, containers. Domain 5 (Identity and Access Management) - container IAM. |

## Extended Certifications

| Certification | Relevant Domains |
|---------------|------------------|
| CCSP (ISC2) | Domain 5 (Cloud Platform and Infrastructure Security) - virtualization in cloud, containers, orchestration. Domain 6 (Cloud Application Security) - container security. |
| CKS (Certified Kubernetes Security Specialist) | Container security, runtime security, supply chain, cluster hardening, microservice vulnerability analysis. |
| CKA (Certified Kubernetes Administrator) | Cluster architecture, workloads, security, networking, storage. |
| Certified Container Security Expert (CCSE) | Container runtime, orchestration, image security, supply chain. |
| VMware Certified Professional - Data Center Virtualization (VCP-DCV) | Hypervisor architecture, vSphere security, VM isolation, NSX. |

## Subcategory to Certification Matrix

| # | Subcategory | Security+ | CySA+ | CISSP | CCSP | CKS | VCP-DCV |
|---|-------------|-----------|-------|-------|------|-----|---------|
| 01 | [Hypervisors](./01%20Hypervisors/README.md) | X | X | X | X | - | X |
| 02 | [VM Escape](./02%20VM%20Escape/README.md) | X | X | X | X | X | X |
| 03 | [Containers](./03%20Containers/README.md) | X | X | X | X | X | - |
| 04 | [Sandboxes](./04%20Sandboxes/README.md) | X | X | X | X | X | X |
| 05 | [Orchestration](./05%20Orchestration/README.md) | X | X | X | X | X | X |

## Study Notes

- **Security+ / CySA+ / CISSP** - the conceptual model of hypervisor vs container isolation, the shared responsibility model, and the common attack classes (VM escape, container escape, supply chain) are enough for the core certifications. Focus on the "why", not on specific tooling.
- **CCSP** - cloud-native virtualization (Kubernetes, serverless isolation, multi-tenant hypervisors) is a frequent exam topic. Focus on shared responsibility and the cloud provider's boundaries.
- **CKS / CKA** - hands-on. Focus on Kubernetes runtime security, RBAC, network policies, pod security standards, and supply chain (image scanning, signed images).
- **VCP-DCV** - on-premises virtualization. Focus on vSphere security, VM isolation, network segmentation, and hardening guidelines.

## References

- CompTIA Security+ SY0-701 exam objectives - https://www.comptia.org/certifications/security
- CompTIA CySA+ CS0-003 exam objectives - https://www.comptia.org/certifications/cybersecurity-analyst
- ISC2 CISSP exam outline - https://www.isc2.org/certifications/cissp
- ISC2 CCSP exam outline - https://www.isc2.org/certifications/ccsp
- CNCF CKS certification - https://www.cncf.io/certification/cks/
- VMware VCP-DCV certification - https://www.vmware.com/learning/certification/vcp-dcv.html

