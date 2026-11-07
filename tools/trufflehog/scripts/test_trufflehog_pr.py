import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import trufflehog_pr as pr
import test_trufflehog_scan as fixtures


class PrRangeTests(unittest.TestCase):
    setUp = fixtures.TrufflehogTests.setUp

    def test_exact_range_covers_deleted_history(self):
        ancestor, count = pr.range_boundary(self.repo, self.first, self.head)
        self.assertEqual((self.first, 1), (ancestor, count))
        self.assertFalse((self.repo / "fixture.txt").exists())

    def test_missing_wrong_and_empty_boundaries_do_not_start_a_scanner(self):
        for base, head in [("bad", self.head), (self.first, "a" * 40), ("b" * 40, self.head), (self.head, self.head)]:
            with self.subTest(base=base), self.assertRaises(pr.ScanError):
                pr.range_boundary(self.repo, base, head)

    def test_shallow_alternates_and_changed_policy_inputs_fail_closed(self):
        (self.repo / ".git/shallow").write_text(self.first + "\n", encoding="utf-8")
        with self.assertRaises(pr.ScanError):
            pr.range_boundary(self.repo, self.first, self.head)

    def test_incomplete_scan_never_becomes_a_successful_findings_report(self):
        with patch("trufflehog_scan.run_scan", side_effect=pr.ScanError("scan timed out; coverage incomplete")):
            with self.assertRaises(pr.ScanError):
                pr.run_pr_scan(self.repo, self.first, self.head)

    def test_workflow_runs_base_scripts_without_cloud_credentials_or_candidate_install(self):
        workflow = (Path(__file__).resolve().parents[1] / "reference/workflows/trufflehog-pr.yml.example").read_text(encoding="utf-8")
        self.assertIn("python3 -B trusted/scripts/trufflehog_scan.py", workflow)
        self.assertIn("github.event.pull_request.base.sha", workflow)
        self.assertNotIn("pull_request_target:", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("npm ci", workflow)
        contract = (Path(__file__).resolve().parents[1] / "reference/workflows/trufflehog-contract-ci.yml.example").read_text(encoding="utf-8")
        self.assertEqual(contract.count("- scripts/test_trufflehog*.py"), 2)


if __name__ == "__main__":
    unittest.main()
