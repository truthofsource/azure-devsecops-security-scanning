# Trivy: strengths and tradeoffs

| Strength | Why it is useful in this implementation |
| --- | --- |
| **Package and image visibility** | Check supported operating-system and application packages inside a container, plus the recorded package versions in source code. These checks cover different parts of a release. |
| **Reusable inventory** | Create software lists in the standard CycloneDX and SPDX JSON formats. These lists, called SBOMs, help compare releases and check packages again later. |
| **Repeatable release evidence** | Record the scanner version, the checked files and the exact release. Confirm that the scan finished before applying the release rules. |

| Limit | Practical response |
| --- | --- |
| Coverage follows target | Checking source files is different from checking the released container. A package finding does not by itself prove the application can be attacked. |
| Database age matters | The local reference used an existing DB without updating it; no vulnerability result is timeless. |
| Threshold is policy | Unfixed and Medium findings remain visible even when a fixable High/Critical threshold does not block. |

## Choosing the right layer

Trivy inventories/scans supported packages and images, with separate configuration capability. TruffleHog focuses on possible credentials and Git-history coverage. Checkov focuses on infrastructure definitions and policy rules. ZAP, used separately by the platform, exercises HTTP behavior; it is not replaced by any of these source scans.

Keep all three outputs tied to an explicit target and date. Tool severity, an organization's release threshold, exploitability and a business risk-acceptance decision are different concepts. A passing narrow check does not certify the entire environment.

The upstream tool documentation describes broader capabilities than every mode used here. The implemented mode and its privacy/network restrictions are established by mapped source and dated tests. [Official Trivy reference](https://trivy.dev/docs/latest/scanner/vulnerability/).
