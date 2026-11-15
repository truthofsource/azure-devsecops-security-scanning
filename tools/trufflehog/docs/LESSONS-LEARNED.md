# Troubleshooting lessons from the actual platform

These are historical engineering incidents summarized from maintained internal records. They are not newly reproduced tests, a fresh cloud inventory or instructions to repeat a consumed operation. Names, resource identifiers, private payloads and credentials are excluded.

## A candidate was a public package hash, not a credential

**What happened.** Three retained detector candidates required review before they could be described as exposed secrets.

**What the evidence showed.** The reconciliation checked the individual values privately and confirmed public package-hash provenance. A detector match alone had not established a working credential or unauthorized access.

**What changed and how it was checked.** The candidates were classified individually without publishing raw candidate values or suppressing the detector family. Future matches remain subject to review.

**What to carry forward.** Preserve the distinction between a candidate, confirmed exposure and remediation. If a real credential is exposed, deleting the text from the current file is not credential revocation or removal from Git history.

Source record: `docs/reviews/pr822-reconciliation-20261105.md; recorded PR 822 secret-candidate reconciliation`. These internal paths identify provenance; they are not public file links.

## Evidence and project boundaries

The local examples and screenshots in this repository remain separate from the dated hosted incidents above. A new documentation summary does not establish another successful deployment, restore, security scan or business transaction. Follow the repository’s existing validation guide for the commands and limits of the runnable reference.

The practical sequence is: identify the failing boundary, preserve safe correlation evidence, reconcile any uncertain result, apply only the relevant repair and verify the resulting state. A completed local command is not interchangeable with a completed cloud operation.
