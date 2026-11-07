# Scaling Checkov checks

**Terms used here:** A digest is a file or container fingerprint used to confirm the exact version. An artifact is a file produced for a release, such as an application ZIP or container image.

Measure scan duration, queue time, inventory size, package/history/module coverage, finding churn and remediation age. Optimize only after proving which work consumes time.

| Growth issue | Potential improvement | Preserve |
| --- | --- | --- |
| More source changes | Select affected targets from a complete diff; scan broadly when scope is unknown | No silent coverage gap for shared inputs |
| Repeated dependency/image checks | Reuse validated reports for the exact digest/commit within a defined freshness policy | Database/policy identity and expiry |
| Scanner database/image downloads | Cache pinned tooling and identified databases safely | Integrity checks and visible cache age |
| Larger Git history | Keep full-history baselines separate from exact PR ranges | Deleted-history coverage, merge-base and complete history |
| More infrastructure modules | Stage tracked inputs and record external-module/graph limits | Parse/skip counts and per-occurrence identity |
| Too much finding noise | Assign owners, next evidence and narrow expiring exceptions where authorized | Original unresolved findings and counts |

Avoid candidate-controlled scripts and credentials in scanners as concurrency grows. Bound output size/time and distinguish an incomplete job from a passing job. Restrict who can change tooling/policy, not just who can read a report.

Local scans do not consume hosted Actions minutes; hosted runs and retained artifacts do. The manual-only public workflow avoids automatic spending. Parallel jobs can reduce wall time while increasing concurrency and downloads. No cost limit, cache service or cloud capacity was changed here.
