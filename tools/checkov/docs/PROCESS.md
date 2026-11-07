# Scope, trust and integration

1. Identify exactly what will be checked: a source-code version and its package list, a container build, or a defined part of Git history.
2. Run the trusted scanner and rules separately from the proposed code changes. Confirm the scanner’s exact version and file or image fingerprint.
3. Leave credentials and unrelated private files out of the scan input. Require a clear result showing that the scan finished.
4. Before reviewing findings, check that the report is readable, the expected files or packages were checked, and the scanner finished correctly.
5. Apply the actual mode's policy: record findings for review or enforce an explicitly selected threshold. Never confuse execution failure with an ordinary findings exit code.
6. Apply and test suitable fixes, keep unresolved issues visible, and record exactly which version the result describes.

The real platform’s workflow is included as [an inert example](../reference/workflows/security-checkov-baseline.yml.example). It references the complete platform tooling/paths and is not a drop-in deployment workflow for this smaller repository. Its automatic triggers do not run because it is outside .github/workflows. The public test workflow checks the input/output rules and runs only when started manually. It was not run on GitHub for this update.

No Azure login, new cloud role or Terraform apply is necessary for these local checks. Scanning permission and deployment permission should remain separate. Check separately that the GitHub plan supports the required rules, that those rules are enforced, and that the correct identity approves a release. A workflow file alone does not prove that every release path is protected.
