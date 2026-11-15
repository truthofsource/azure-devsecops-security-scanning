# Operating and troubleshooting OWASP ZAP

| Symptom | Investigate | Evidence limit / next step |
| --- | --- | --- |
| Only the sign-in page is observed | Check the prepared identity, session lifetime and actual protected requests | A logged-in browser alone is not scanner access to every route |
| Admin probe returns 400 or 503 | Compare the defined error-path probe and expected response | An authorized negative-input probe is not a successful business operation |
| Caregiver receives a protected record | Preserve the exact role/route observation and stop the test | Do not widen the fixture scope or reinterpret an unexpected allow as a pass |
| PDF helper fails while the preview is visible | Check download selection, saveAs handling and internal viewer resources | Correct the harness while preserving access controls and external-traffic restrictions |
| No alerts in the sample | Verify request count, roles, target and passive/active mode | A bounded read-only sample is not a whole-platform security assessment |

[Documented troubleshooting lessons](LESSONS-LEARNED.md) explain the historical incidents and their limits. Keep the selected source or digest, tool version, expected coverage, completion status and safe failure stage with the result.

Keep raw possible secrets, tokens, employee data, authenticated browser state and signed URLs out of public reports. Local examples use fictional inputs; live scans and changes require their own intended target and scope. Do not weaken controls or repeat a business operation to obtain a cleaner test result.
