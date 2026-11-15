# Consolidated project material

Tool-specific implementations and evidence. Each subfolder retains its original implementation, tests, evidence and build instructions so the useful work remains available in one project.

| Component | Preserved material |
| --- | --- |
| [trivy-vulnerability-management](../tools/trivy/README.md) | 47 source/evidence files; local tests run from the component folder. |
| [checkov-azure-infrastructure-security](../tools/checkov/README.md) | 38 source/evidence files; local tests run from the component folder. |
| [trufflehog-secret-detection](../tools/trufflehog/README.md) | 36 source/evidence files; local tests run from the component folder. |
| [owasp-zap-authenticated-security](../tools/zap/README.md) | 29 source/evidence files; local tests run from the component folder. |

Nested `.github/workflows` directories are teaching references, not active GitHub Actions workflows. Original Git history is retained in verified local recovery bundles; each component also records its source commit and original file fingerprints in `CONSOLIDATION-ORIGIN.json`.

Historical acceptance receipts and fixture values remain dated evidence, not instructions to repeat live deployments or claims of new hosted validation.
