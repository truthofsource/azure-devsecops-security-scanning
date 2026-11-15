# Operating and troubleshooting Checkov

| Symptom | Investigate | Evidence limit / next step |
| --- | --- | --- |
| A rule flags intentional isolation | Inspect the resolved resource configuration, real caller needs and alternate control | Do not broaden trusted-service bypass just to clear a generic recommendation |
| Fewer failures, different pass count | Compare the resources and checks actually evaluated | A missing previous pass is a coverage difference, not a newly passing control |
| Plan looks narrow, runtime differs | Compare exact service preimages and post-operation readback | The documented storage-setting addition required a separate narrow restoration |
| Null versus false changes a result | Inspect the exact field, after_unknown values and provider representation | Do not apply blanket normalization or lifecycle ignores |
| IaC scan passes | Inspect live state and functional checks separately | A source-policy pass does not prove Azure connectivity or deployed compliance |

[Documented troubleshooting lessons](LESSONS-LEARNED.md) explain the historical incidents and their limits. Keep the selected source or digest, tool version, expected coverage, completion status and safe failure stage with the result.

Keep raw possible secrets, tokens, employee data, authenticated browser state and signed URLs out of public reports. Local examples use fictional inputs; live scans and changes require their own intended target and scope. Do not weaken controls or repeat a business operation to obtain a cleaner test result.
