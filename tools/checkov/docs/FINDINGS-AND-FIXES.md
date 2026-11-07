# Findings, fixes and evidence

**Terms used here:** A fixture is test data or a test setup used instead of real business records.

The recorded full-source baseline evaluated 508 resources over 228 inputs: 211 checks passed, 106 failed, with no skips or parse errors. Each remaining occurrence retained its next-evidence requirement rather than being silently suppressed.

### Triage without hiding failures

The [106-occurrence register](../data/platform-open-findings.csv) preserves the source resource, rule ID, category, disposition and next evidence. Network controls, logging/retention, key lifecycle and availability/cost remain distinct categories. A source-level graph match is not deployed proof. Paid tiers and additional private endpoints were not activated for scanner score improvements.

The local fixture narrows two storage settings: Shared Key and nested anonymous access. Some related checks improve, but other failures remain. A passing related rule is not a claim that a different feature, such as a SAS policy, was independently deployed.


## Evidence categories

| Category | Meaning |
| --- | --- |
| Dated platform finding record | Actual recorded source-review/scanning history, with its date and limits |
| Local scanner execution | Genuine run against only the public test examples, where recorded in Validation |
| Parser/gate demonstration | Fictional data exercising the actual decision code |
| Cloud/runtime acceptance | Separate target-specific evidence, not performed for this portfolio |

A fresh network-isolated scan of two public storage fixtures produced 14 passed and 16 failed checks, with no skips or parse errors. Specific rules changed from Failed to Passed after the narrow fixture changes; unresolved controls stayed visible. No Terraform was applied.

Do not add together findings from different targets, scanner versions or dates as though they were unique current vulnerabilities. Do not rewrite an expired baseline, widen a suppression or activate an expensive service just to reduce a static count. A remediation needs a clear source change, relevant tests and, when applicable, later live acceptance.
