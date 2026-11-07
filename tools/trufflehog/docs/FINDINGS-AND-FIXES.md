# Findings, fixes and evidence

The implementation catches removed history, refuses incomplete coverage and keeps raw candidate fields private. A recorded reconciliation reviewed three detector candidates and confirmed they were public package hashes; it did not create broad secret suppressions.

### Privacy and history coverage

The actual implementation rejects incomplete/shallow/rewritten history, unsupported local Git configuration, a moved head and mismatched completion records. PR mode binds base, head and merge base. Raw candidate output and diagnostic files remain private and bounded; the safe parser excludes Raw, Redacted and ExtraData values from its aggregate output.

The public wrapper's allowed origin is changed to this project; it must not be broadened to arbitrary repositories as an unexplained convenience. Exact, expiring suppressions are separate from global scanner ignores. If a real credential is exposed, revoke/rotate it and review usage; removing a file or rewriting history alone does not revoke it.


## Evidence categories

| Category | Meaning |
| --- | --- |
| Dated platform finding record | Actual recorded source-review/scanning history, with its date and limits |
| Local scanner execution | Genuine run against only the public test examples, where recorded in Validation |
| Parser/gate demonstration | Fictional data exercising the actual decision code |
| Cloud/runtime acceptance | Separate target-specific evidence, not performed for this portfolio |

The parser demonstration accepts a fictional candidate and emits only counts. A separate real scanner test uses a disposable repository and an unregistered generated key that is committed and deleted; its exact observed outcome is recorded in Validation. No test key or raw scanner output is published.

Do not add together findings from different targets, scanner versions or dates as though they were unique current vulnerabilities. Do not rewrite an expired baseline, widen a suppression or activate an expensive service just to reduce a static count. A remediation needs a clear source change, relevant tests and, when applicable, later live acceptance.
