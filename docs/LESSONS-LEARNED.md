# Troubleshooting lessons from the actual platform

These are historical engineering incidents summarized from maintained internal records. They are not newly reproduced tests, a fresh cloud inventory or instructions to repeat a consumed operation. Names, resource identifiers, private payloads and credentials are excluded.

## An empty result was missing coverage, not finding nothing

**What happened.** A Trivy command could finish without the expected operating-system package results.

**What the evidence showed.** The pinned Ubuntu inventory path needed lsb-release as well as the package database. Staging only os-release did not establish the expected coverage. An empty report was therefore insufficient evidence of a clean target.

**What changed and how it was checked.** The validation path required the distribution metadata and a nonempty expected OS-package inventory. Failed or incomplete reports stayed visible rather than being converted into zero-vulnerability success.

**What to carry forward.** Prove what the scanner examined before interpreting its findings count. Preserve the exact target, tool/database evidence, expected inventory and completion status; this specific metadata repair is not a universal explanation for every empty report.

Source record: `docs/troubleshooting/vulnerability-scanning.md — November 4 compatibility and host-inventory lessons`. These internal paths identify provenance; they are not public file links.

## An AccountKey metric did not identify a key-using application

**What happened.** A storage metrics sample contained successful AccountKey-classified transactions, initially raising the question of which callers still depended on a key.

**What the evidence showed.** Already-key-disabled control accounts also showed such metadata calls. A bounded experiment using only Entra-authenticated ARM reads produced additional AccountKey-classified activity without a client blob-data request or key retrieval in that experiment. Aggregate classification could not identify an individual key-bearing application.

**What changed and how it was checked.** The investigation combined the controlled observation with actual identity/configuration review and archive/recovery preflights. A one-field host-storage Shared Key disable was then applied and checked independently, preserving app settings, identities, bindings and power states. This did not attribute every historical transaction or resolve separate state-account questions.

**What to carry forward.** Treat a security signal as evidence to investigate, not a complete caller inventory. Confirm the affected operation and identity before changing access, and keep a narrow experiment’s limits visible.

Source record: `docs/reviews/security-delivery-followthrough-20261105.md — Shared Key trace: management metrics need interpretation`. These internal paths identify provenance; they are not public file links.

## The test helper failed while the PDF was visible

**What happened.** Some protected-PDF checks stopped at a helper assertion or download operation even while the user could see the saved PDF.

**What the evidence showed.** Recorded causes included a browser-server client using Download.path(), an overbroad request mock intercepting internal viewer resources and a download wait matching the PDF viewer event rather than the intended PNG. These are distinct failures, not proof of a product authorization or PDF defect.

**What changed and how it was checked.** The relevant helpers used saveAs to an owned temporary file, checked actual bytes, preserved required viewer resources and selected the intended download. The fixes kept external traffic restrictions and access-denial checks rather than weakening the application to satisfy a faulty test.

**What to carry forward.** Validate the observation tool as well as the product. Authorized error-path probes can establish an access boundary without proving a successful business operation, and an attached frame is weaker evidence than visible rendering and correct downloaded bytes.

Source record: `docs/troubleshooting/vulnerability-scanning.md — November 4 compatibility and host-inventory lessons; docs/troubleshooting/employee-badge-photos.md — Portal test captures the wrong download`. These internal paths identify provenance; they are not public file links.

## Evidence and project boundaries

The local examples and screenshots in this repository remain separate from the dated hosted incidents above. A new documentation summary does not establish another successful deployment, restore, security scan or business transaction. Follow the repository’s existing validation guide for the commands and limits of the runnable reference.

The practical sequence is: identify the failing boundary, preserve safe correlation evidence, reconcile any uncertain result, apply only the relevant repair and verify the resulting state. A completed local command is not interchangeable with a completed cloud operation.

## Related project details

- [Trivy coverage details](https://github.com/truthofsource/trivy-vulnerability-management/blob/main/docs/LESSONS-LEARNED.md)
- [Checkov configuration review](https://github.com/truthofsource/checkov-azure-infrastructure-security/blob/main/docs/LESSONS-LEARNED.md)
- [TruffleHog candidate classification](https://github.com/truthofsource/trufflehog-secret-detection/blob/main/docs/LESSONS-LEARNED.md)
- [ZAP observation and PDF checks](https://github.com/truthofsource/owasp-zap-authenticated-security/blob/main/docs/LESSONS-LEARNED.md)
