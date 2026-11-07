# Commands and expected results

## Standard-library checks

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
python -B scripts/preview.py --port 8138
```

Use Python 3.12 and Git for history/staging tests. Optional scanner integration cases require the explicit pinned tool/image and are otherwise skipped. The viewer is at http://127.0.0.1:8138; Ctrl+C stops it. It runs only the fictional parser example, not a live scan.

## History and PR commands

```bash
python -B scripts/trufflehog_scan.py --repo /path/to/isolated-clean-clone --expected-head "$HEAD_SHA"
python -B scripts/trufflehog_pr.py --repo /path/to/isolated-clean-clone --base "$BASE_SHA" --head "$HEAD_SHA"
```

These commands enforce the public repository origin, complete isolated Git directory and selected pin. Docker must be on PATH. The wrapper first acquires the pinned public scanner image, then runs it with network none, read-only source mount, no verification/update and bounded private output. They are not permission to scan arbitrary private repositories.

The actual real-history test creates an unused key in a disposable repository, commits and deletes it, and requires one PrivateKey candidate without publishing its value. Set WORKFORCE_TRUFFLEHOG_CONTAINER=1 only when explicitly running that integration case; the default suite does not download/run the scanner. No generated test key is included in the public project or used with any provider.
