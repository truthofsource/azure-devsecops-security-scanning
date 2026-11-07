# Source mapping

**Terms used here:** A fixture is test data or a test setup used instead of real business records.

[Machine source map](source-map.json) records original file hashes and public destinations. Identifying platform names and paths use consistent examples. Actual credentials, runtime values, raw secret output, employee data and private Git history are excluded.

The core Checkov wrapper/parser and tests that existing behavior still works come from the implemented platform. Production workflows are retained as inert .example files outside .github/workflows. The public viewer and fictional demonstration are new reference code and are labeled as such.

The Trivy subset omits only the full-platform Dockerfile-register equality test, because that complete set of private build contexts is not published; the other original scan/scope tests remain. Its image register documents source selection but does not make every referenced platform image buildable here. Its copied Dockerfile expects the complete private Backstage workspace.

The TruffleHog public origin allowlist targets this repository, with matching test behavior. Workflow-tests of the agreed input and output rules read the inert example paths. Optional real scanner tests are reported separately and keep generated test keys only in disposable local repositories.

The Checkov wrapper retains tracked-only input staging, hash-locked dependencies, credential-free environment and report-for-review mode. Its before/after storage examples are new limited fixtures based on actual control fields; the mapped storage module is a reference, not a complete deployment root.

Recorded November 5 platform counts remain historical evidence. Locally scanned public examples are separate targets and cannot clear those findings.
