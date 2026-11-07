# Commands and expected results

## Standard-library checks

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
python -B scripts/preview.py --port 8138
```

Use Python 3.12 and Git for history/staging tests. Optional scanner integration cases require the explicit pinned tool/image and are otherwise skipped. The viewer is at http://127.0.0.1:8138; Ctrl+C stops it. It runs only the fictional parser example, not a live scan.

## Pinned Trivy

```bash
python -B scripts/security_scan.py install --directory ./scanner-tools
trivy --version
trivy fs --scanners vuln --skip-db-update --offline-scan --include-dev-deps --list-all-pkgs --format json --output reports/vulnerabilities.json apps
trivy config --misconfig-scanners terraform --include-non-failures --format json --output reports/configuration.json infra
trivy convert --format cyclonedx --output reports/sbom.cyclonedx.json reports/vulnerabilities.json
trivy convert --format spdx-json --output reports/sbom.spdx.json reports/vulnerabilities.json
```

Create the ignored reports directory and put the verified executable on PATH, or use its exact path. Existing DB mode needs a previously acquired database; if absent, initialize it deliberately rather than treating failure as clean. Configuration checks may download public policy bundles unless prepared locally. No Azure credential is required.

For a selected local/authorized image, use `trivy image --scanners vuln --format json --output reports/image.json "$IMAGE_DIGEST"`. Source and image flags differ: include-dev-deps belongs to the filesystem scan here, not the image scan. No private registry image was pulled for this portfolio.
