# Operating and troubleshooting TruffleHog

| Symptom | Investigate | Evidence limit / next step |
| --- | --- | --- |
| Candidate resembles a package hash | Verify the exact private candidate against public package provenance | Classify individually; do not publish raw matches or suppress a detector family |
| Current file is clean, history still reports a match | Inspect the intended history range and exact occurrence privately | Deleting a line is not credential revocation or history removal |
| A real credential is confirmed exposed | Use the owner’s revocation/rotation and incident procedure | Do not test the secret against unrelated systems or paste it into a report |
| History or report is incomplete | Check the scanned refs, clone depth and completion evidence | No candidate output does not establish full-history coverage |
| A prior reviewed candidate recurs | Match the exact occurrence and evidence | A past false positive is not a permanent exemption for future values |

[Documented troubleshooting lessons](LESSONS-LEARNED.md) explain the historical incidents and their limits. Keep the selected source or digest, tool version, expected coverage, completion status and safe failure stage with the result.

Keep raw possible secrets, tokens, employee data, authenticated browser state and signed URLs out of public reports. Local examples use fictional inputs; live scans and changes require their own intended target and scope. Do not weaken controls or repeat a business operation to obtain a cleaner test result.
