# AI Security

Reference material on artificial intelligence and machine learning security:
offensive techniques against AI systems and defensive controls to protect them.

> [!CAUTION]
> Authorized use only. All material is provided for educational purposes and authorized testing.<br>
> See [../SECURITY.md](../SECURITY.md) for the full policy.
## Scope

This category covers the attack surface introduced by AI and ML systems:
large language models (LLMs), retrieval-augmented generation (RAG) pipelines,
autonomous agents, the model supply chain, and the infrastructure that serves
them. Each topic is written in a two-track format: offensive (how the technique
works, how to test for it) and defensive (how to prevent and detect it).

## Format

Every file follows the two-track structure:

- **Offensive track** - reconnaissance, attack vectors, exploitation recipes, post-exploitation.
- **Defensive track** - preventive controls, detection controls, verification.

Section headers have no suffix - the section names themselves make the
track clear. See WRITEUPS/ for HTB walkthroughs and APPLICATIONS/ for
web application security.

## Subcategories

| # | Subcategory | Files | Focus |
|---|-------------|-------|-------|
| 01 | [OWASP-LLM-Top-10-2026](./01%20OWASP-LLM-Top-10-2026/) | 10 | OWASP LLM Top 10 (2026) threats and mitigations |
| 02 | [RAG-and-Embeddings](./02%20RAG-and-Embeddings/) | 4 | RAG pipelines, vector databases, embedding attacks |
| 03 | [Agents-and-MCP](./03%20Agents-and-MCP/) | 4 | Autonomous agents, Model Context Protocol (MCP) security |
| 04 | [AI-Supply-Chain](./04%20AI-Supply-Chain/) | 4 | Model provenance, dataset poisoning, dependency attacks |
| 05 | [OSAI-Prep](./05%20OSAI-Prep/) | 3 | Offensive Security AI (OSAI) certification preparation |

## Related Categories

- [APPLICATIONS](../APPLICATIONS/) - web, mobile, and API security reference.
- [INFRASTRUCTURE](../INFRASTRUCTURE/) - infrastructure attack and defense (AD, Windows, Linux, network).
- [CLOUD](../CLOUD/) - cloud security reference (AWS, Azure, GCP, Kubernetes, Serverless, IaC).

## Authorized Use Only

The techniques in this category are for authorized security testing,
CTF environments, and educational purposes only. Do not use them against
systems you do not own or have explicit written permission to test.
See SECURITY.md in the repository root.

## References

- OWASP Top 10 for LLM Applications - https://owasp.org/www-project-top-10-for-large-language-model-applications/
- MITRE ATLAS - https://atlas.mitre.org/
- NIST AI Risk Management Framework - https://www.nist.gov/itl/ai-risk-management-framework

