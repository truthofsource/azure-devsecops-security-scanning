# TruffleHog: strengths and tradeoffs

**Terms used here:** An artifact is a file produced for a release, such as an application ZIP or container image.

| Strength | Why it is useful in this implementation |
| --- | --- |
| **Deleted-history coverage** | Search earlier Git versions for possible credentials, even after a file is deleted. |
| **Credential-focused detectors** | Look for patterns used by passwords, keys and tokens. The tool can optionally check whether a credential works; this setup disables that step and reviews matches privately. |
| **Safer PR trust boundary** | Use scanning code from the trusted base version, check the exact proposed change and publish counts only. The proposed code cannot choose its own rules or expose possible secret values. |

| Limit | Practical response |
| --- | --- |
| A candidate needs review | A match does not prove that a working credential was exposed. Some matches, such as public package hashes, need review before a decision. |
| Scope is explicit | A main-history or PR-range scan is not every branch, ref, artifact, image or external mailbox. |
| Offline means no live validity test | Network none and no-verification reduce exposure, but cannot establish whether a candidate works against a provider. |

## Choosing the right layer

Trivy inventories/scans supported packages and images, with separate configuration capability. TruffleHog focuses on possible credentials and Git-history coverage. Checkov focuses on infrastructure definitions and policy rules. ZAP, used separately by the platform, exercises HTTP behavior; it is not replaced by any of these source scans.

Keep all three outputs tied to an explicit target and date. Tool severity, an organization's release threshold, exploitability and a business risk-acceptance decision are different concepts. A passing narrow check does not certify the entire environment.

The upstream tool documentation describes broader capabilities than every mode used here. The implemented mode and its privacy/network restrictions are established by mapped source and dated tests. [Official TruffleHog reference](https://github.com/trufflesecurity/trufflehog).
