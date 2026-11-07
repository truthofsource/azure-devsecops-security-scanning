"""Separate PR command using the trusted shared offline range implementation."""
import argparse
import json
import sys
from pathlib import Path
from trufflehog_scan import ScanError, ScanOutputError, range_boundary, run_pr_scan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run_pr_scan(args.repo, args.base, args.head), sort_keys=True))
        return 0
    except (ScanError, ScanOutputError) as problem:
        print(json.dumps({"schema_version": 3, "completed": False, "coverage_complete": False,
                          "outcome": "incomplete", "error": str(problem)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
