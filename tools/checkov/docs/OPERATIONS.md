# Operating and troubleshooting Checkov

**Terms used here:** An artifact is a file produced for a release, such as an application ZIP or container image. A fixture is test data or a test setup used instead of real business records.

| Symptom | Investigate | Response |
| --- | --- | --- |
| Empty report | Execution status, expected inventory and target selection | Mark incomplete; do not report zero findings |
| Version/pin mismatch | Trusted tool image/archive hash and selected policy | Stop before attaching success to the target |
| New finding after a rescan | Target/database/policy changes and exact occurrence | Review the real difference, not only total count |
| Findings exit code | Mode-specific documented status and valid report | Distinguish a finding from a runtime/parser failure |
| Timeout or partial coverage | History/package/module coverage and resource limits | Preserve incomplete state; use a bounded reviewed retry |
| Possible secret | Private location/owner and credential lifecycle | Keep raw values private; revoke/rotate confirmed exposure |
| Static configuration disagreement | Exact resource/variable graph and alternate control | Gather evidence; avoid a broad rule suppression |

The project itself does not upload scanner reports to a third party. The raw secret-scanner output is never a public artifact. Public vulnerability/configuration fixtures contain no real targets; actual private platform reports remain outside the repository.

To inspect GitHub integration, use repository Actions â†’ the relevant workflow â†’ its selected run and safe summary. Review workflow permissions, trusted/candidate checkout identities, selected commit and how long release files are kept. Do not dispatch the production reference files or paste raw findings containing possible credentials into a PR.
