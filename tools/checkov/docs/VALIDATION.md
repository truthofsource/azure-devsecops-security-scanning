# Local validation — November 6, 2026

**Terms used here:** A fixture is test data or a test setup used instead of real business records.

| Check | Result |
| --- | --- |
| Original input/output rule tests | 10 passed; 0 optional integration cases skipped in the default suite |
| Demo | Actual parser/decision code exercised with explicitly fictional inputs |
| Browser | Three strength cards, all tabs and 390px layout passed |
| Browser isolation | Zero external requests and zero page errors |
| Workflow | Manual public validation; no hosted dispatch |

The genuine local scanner report/results under data/ cover only this project's public test examples. They do not rescan or clear the full platform.

[Machine-readable results](validation-results.json) record exact scope. Historical November 5 platform findings are separate from November 6 public examples. Trivy's local vulnerability result used an existing database with updates disabled. Checkov's direct local scan used the existing selected Linux tooling with network none. The original Checkov wrapper is exercised by contracts; the fresh fixture scanner invocation was direct and its report was then validated by that wrapper's actual parser.

No Terraform apply, Azure query/start, credential-provider verification, release, package repair in the private platform or hosted Actions run occurred. Pure tests are not proof of deployed image freshness, full-history coverage outside the selected source, or live cloud compliance.
