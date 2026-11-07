# Commands and expected output

Run from the project root:

```bash
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B scripts/demo.py
```

Nine original Python tests of the agreed input and output rules passed. The fictional probe exercises the actual ten-request evaluator.

```bash
python -B scripts/preview.py --port 8139
```

Open http://127.0.0.1:8139. Ctrl+C stops the loopback-only viewer. Use Python 3.12.

The public API target is deliberately api.workforce.invalid. Run only contracts/demonstrations here. A hosted test needs an explicitly reviewed target, routes, method limits, distinct role accounts, private short-lived tokens and cleanup. No fresh sign-in or scan is required for this project.
