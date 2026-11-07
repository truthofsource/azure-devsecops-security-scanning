# Combined-project checks - November 6, 2026

This pass verified that combining the existing projects preserves their behavior
and evidence. It did not run new cloud scans or remediate additional findings.

| Check | Result |
| --- | --- |
| Component file hashes against the four captured public commits | Passed for all 141 copied files. |
| TruffleHog reference suite | 23 discovered: 21 passed; two optional real-CLI/container integration tests skipped because their prerequisites were not requested. |
| Checkov reference suite | 10 passed. |
| Trivy reference suite | 12 passed. |
| Authenticated ZAP reference suite | Nine passed. |
| Four fictional demonstrations | Completed with their expected review/blocked outcomes. |
| Root manual-only workflow | Actionlint passed. |
| Relative Markdown links | Passed. |
| Trivy filesystem secret scan of the combined tree | Completed with exit zero; no secret finding reported. This was not a vulnerability scan. |
| Public README at the exact published commit | Matched the local document after line-ending normalization. |

Total: 54 discovered tests, 52 passed and two optional integration tests skipped.
No GitHub Actions run, Azure deployment, live ZAP traffic or credential validation
was triggered for this consolidation. Existing screenshots remain local reference
views, not fresh production captures. The scan results in the README remain historical
results; consult the individual component evidence for their original scope.

## Plain-language review - November 7, 2026

The main overview now starts with the business problem, the solution and the
practical outcome. Technical commands and detailed results remain available in
expandable sections and linked guides. Links, heading anchors, formatting and
expandable sections were checked. Earlier code-test and cloud results remain
historical; this wording pass did not repeat those tests.
