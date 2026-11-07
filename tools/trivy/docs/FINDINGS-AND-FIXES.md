# Findings, fixes and evidence

**Terms used here:** A fixture is test data or a test setup used instead of real business records.

The recorded compatible dependency repairs removed seven reported occurrences without a broad major-version override. The source scan still retained 21 Medium and one Low occurrence; these were not described as a clean deployment.

### Recorded compatible fixes

| Dependency | Selected repair | Why it matters |
| --- | --- | --- |
| Backstage catalog backend | 4.0.0 Ã¢â€ â€™ 4.0.2 | Repair the affected catalog-location validation path |
| fast-uri | 3.1.8 Ã¢â€ â€™ 3.1.9 | Address URI scheme/host/path advisories without forcing a new major |
| qs | Compatible 6.x ranges Ã¢â€ â€™ 6.16.2 | Repair hostile query-array serialization while preserving newer instances |
| postcss-selector-parser | Affected 6.x/7.x lines Ã¢â€ â€™ their compatible patch | Avoid breaking consumers by imposing one major on every parent |

The dated source evidence went from 26 Medium/three Low to 21 Medium/one Low occurrences. The seven removed occurrences and exact advisory identifiers are in [the platform finding record](../data/platform-findings.json). Remaining infrastructure findings and expired-baseline state are separate from dependency thresholds. These are recorded source repairs, not a new scan or deployment of every live image.


## Evidence categories

| Category | Meaning |
| --- | --- |
| Dated platform finding record | Actual recorded source-review/scanning history, with its date and limits |
| Local scanner execution | Genuine run against only the public test examples, where recorded in Validation |
| Parser/gate demonstration | Fictional data exercising the actual decision code |
| Cloud/runtime acceptance | Separate target-specific evidence, not performed for this portfolio |

A real local scan of the public API lockfile inventoried six packages and reported zero vulnerabilities against the existing local database. Configuration fixtures were scanned separately, and both CycloneDX and SPDX JSON were generated. The test-only gate demonstration intentionally blocks one fixable High finding while retaining all three raw fixture findings.

Do not add together findings from different targets, scanner versions or dates as though they were unique current vulnerabilities. Do not rewrite an expired baseline, widen a suppression or activate an expensive service just to reduce a static count. A remediation needs a clear source change, relevant tests and, when applicable, later live acceptance.
