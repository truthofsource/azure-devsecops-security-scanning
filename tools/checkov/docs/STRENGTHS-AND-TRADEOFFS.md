# Checkov: strengths and tradeoffs

| Strength | Why it is useful in this implementation |
| --- | --- |
| **Early infrastructure feedback** | Check the cloud setup before deployment, while risky settings can still be changed and reviewed in code. |
| **Broad built-in control library** | Use built-in rules to check storage, networks, logs, access and reliability. Add custom rules when the organization needs more specific checks. |
| **Actionable review and prioritization** | Tie each finding to a resource and file, assign follow-up work and record what evidence is needed. A failed rule alone does not prove a system was attacked. |

| Limit | Practical response |
| --- | --- |
| Static context is incomplete | Missing modules, values supplied elsewhere or different ways of meeting a rule may need additional checks. |
| Finding is not exploitability | A failed rule may concern cost, reliability or information the scanner cannot see. It is not proof that a system was compromised. |
| Advisory is not approval | This actual wrapper uses soft-fail for findings; execution, version, parse and coverage errors still fail. It is not a release security gate. |

## Choosing the right layer

Trivy inventories/scans supported packages and images, with separate configuration capability. TruffleHog focuses on possible credentials and Git-history coverage. Checkov focuses on infrastructure definitions and policy rules. ZAP, used separately by the platform, exercises HTTP behavior; it is not replaced by any of these source scans.

Keep all three outputs tied to an explicit target and date. Tool severity, an organization's release threshold, exploitability and a business risk-acceptance decision are different concepts. A passing narrow check does not certify the entire environment.

The upstream tool documentation describes broader capabilities than every mode used here. The implemented mode and its privacy/network restrictions are established by mapped source and dated tests. [Official Checkov reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
