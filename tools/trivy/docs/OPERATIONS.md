# Operating and troubleshooting Trivy

| Symptom | Investigate | Evidence limit / next step |
| --- | --- | --- |
| No package results | Confirm distribution metadata and the expected package database were included | Incomplete coverage is not zero vulnerabilities; see the documented Ubuntu inventory incident |
| Image-source reader fails | Keep the immutable digest and inspect registry-reader authority and the failed reader stage | A Docker-export reader error is not a completed image scan |
| Fixed source, vulnerable running image | Compare source, built image, scanned digest and deployed binding | A source update does not replace the existing runtime image |
| Different finding count after rescan | Compare target inventory, tool/advisory database and policy | A smaller count is not automatically the same coverage |
| Runtime stage builds but browser check is absent | Inspect the selected build target and default verification stage | Do not count a skipped verification stage as a pass |

[Documented troubleshooting lessons](LESSONS-LEARNED.md) explain the historical incidents and their limits. Keep the selected source or digest, tool version, expected coverage, completion status and safe failure stage with the result.

Keep raw possible secrets, tokens, employee data, authenticated browser state and signed URLs out of public reports. Local examples use fictional inputs; live scans and changes require their own intended target and scope. Do not weaken controls or repeat a business operation to obtain a cleaner test result.
