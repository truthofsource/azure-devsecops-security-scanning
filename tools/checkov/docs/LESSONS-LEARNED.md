# Troubleshooting lessons from the actual platform

These are historical engineering incidents summarized from maintained internal records. They are not newly reproduced tests, a fresh cloud inventory or instructions to repeat a consumed operation. Names, resource identifiers, private payloads and credentials are excluded.

## A narrow apply introduced an unrelated legacy setting

**What happened.** A settings reconciliation added a plain AzureWebJobsStorage setting that was absent before the operation.

**What the evidence showed.** The unexpected addition was established by comparing the actual before/after runtime settings. A normalized Terraform view alone was not enough to establish that the keyless runtime configuration had been preserved.

**What changed and how it was checked.** A separately scoped restoration removed only the proven addition and read back the keyless values while preserving the approved changes and other settings. The recorded response did not use a broad apply, account-key fallback or expanded runtime permissions.

**What to carry forward.** Validate achieved service state as well as the proposed plan. Preserve exact preimages and distinguish absent, empty, false and unknown values according to the specific field; do not generalize a one-field repair into blanket ignores.

Source record: `docs/troubleshooting/employee-badge-photos.md — Production preparation and rollback; docs/troubleshooting/stage2-processor-host-storage-authentication.md`. These internal paths identify provenance; they are not public file links.

## An AccountKey metric did not identify a key-using application

**What happened.** A storage metrics sample contained successful AccountKey-classified transactions, initially raising the question of which callers still depended on a key.

**What the evidence showed.** Already-key-disabled control accounts also showed such metadata calls. A bounded experiment using only Entra-authenticated ARM reads produced additional AccountKey-classified activity without a client blob-data request or key retrieval in that experiment. Aggregate classification could not identify an individual key-bearing application.

**What changed and how it was checked.** The investigation combined the controlled observation with actual identity/configuration review and archive/recovery preflights. A one-field host-storage Shared Key disable was then applied and checked independently, preserving app settings, identities, bindings and power states. This did not attribute every historical transaction or resolve separate state-account questions.

**What to carry forward.** Treat a security signal as evidence to investigate, not a complete caller inventory. Confirm the affected operation and identity before changing access, and keep a narrow experiment’s limits visible.

Source record: `docs/reviews/security-delivery-followthrough-20261105.md — Shared Key trace: management metrics need interpretation`. These internal paths identify provenance; they are not public file links.

## Evidence and project boundaries

The local examples and screenshots in this repository remain separate from the dated hosted incidents above. A new documentation summary does not establish another successful deployment, restore, security scan or business transaction. Follow the repository’s existing validation guide for the commands and limits of the runnable reference.

The practical sequence is: identify the failing boundary, preserve safe correlation evidence, reconcile any uncertain result, apply only the relevant repair and verify the resulting state. A completed local command is not interchangeable with a completed cloud operation.
