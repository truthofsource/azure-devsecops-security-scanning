# Strengths, weaknesses, operations and scaling

Measure request/role coverage, session expiry, passive queue completion, scan duration and alert churn. Expand routes only after classifying read/write effects and data sensitivity. A browser-based OAuth session can improve realistic coverage but introduces token lifetime, MFA and redirect handling. Active scans and spiders need their own target/rate/write safety review; they were not enabled by this passive project.

Strength: HTTP behavior and role-sensitive coverage. Weakness: a bounded passive sample misses unseen functionality and active-only weaknesses. Tradeoff: fixed read-only probes minimize operational effect but provide intentionally narrow coverage. Keep raw requests, responses, cookies and tokens private. The safe summary contains only selected alert IDs/risk/counts and status observations.

The reported Admin 400/503 responses belong to deliberate invalid-query/feature-off probes, not successful record reads. Troubleshoot identity first; an Admin signed into both windows invalidates the lower-role test. Verify observed identities and roles before protected calls. Do not describe a private adapter failure as a clean scan.

No cloud capacity, schedule, rate limit or paid service was changed for this project. Manual-only reference CI avoids automatic hosted-minute use.
