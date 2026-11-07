# Commands and expected results

**Terms used here:** A fixture is test data or a test setup used instead of real business records.

## Standard-library checks

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
python -B scripts/preview.py --port 8138
```

Use Python 3.12 and Git for history/staging tests. Optional scanner integration cases require the explicit pinned tool/image and are otherwise skipped. The viewer is at http://127.0.0.1:8138; Ctrl+C stops it. It runs only the fictional parser example, not a live scan.

## Checkov installation and baseline

```bash
python -m venv .venv
python -m pip --python .venv/bin/python install --require-hashes -r security/checkov-requirements.txt
python -B scripts/security_checkov.py --checkov .venv/bin/checkov --source . --output reports/checkov
```

The actual hash-locked file targets Linux/Python 3.12. Use the matching environment; do not install only the .in pin in CI. The source must be an appropriate Git checkout because the wrapper stages tracked Terraform and binds HEAD. Outputs must be new/empty, and raw private reports should remain private.

For a direct public-fixture run in a reviewed Checkov environment:

```bash
checkov --directory infra --framework terraform --download-external-modules false --skip-download --skip-results-upload --soft-fail --output json
```

The wrapper separately enforces version, parsed report, real counts/resources and no parsing errors. Soft-fail applies to findings, not execution failure. Local evidence used the existing pinned Checkov Linux environment with network none; it did not install packages, call Azure or apply the fixtures.
