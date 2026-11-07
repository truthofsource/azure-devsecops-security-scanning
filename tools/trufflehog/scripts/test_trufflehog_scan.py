"""Synthetic contract tests; never scan business records or real credentials."""

import json
import os
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

import trufflehog_scan as scan
from trufflehog_report import ScanOutputError, load_suppressions, parse_findings, validate_completion


def finding(commit, raw="FAKE-TEST-ONLY"):
    return {"DetectorName": "Test", "SourceMetadata": {"Data": {"Git": {
        "commit": commit, "file": "fixture.txt", "line": 1}}}, "Raw": raw,
        "Redacted": raw, "ExtraData": {"secret": raw}}


def completion_log(version="3.99.4"):
    return (json.dumps({"level": "info-0", "msg": "finished scanning",
                        "trufflehog_version": version, "chunks": 2, "bytes": 128}) + "\n").encode()


class TrufflehogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        def git(*args):
            return subprocess.run(["git", "-C", str(self.repo), *args],
                                  capture_output=True, text=True, check=True).stdout.strip()
        git("init", "-b", "main")
        git("config", "user.name", "Synthetic Test")
        git("config", "user.email", "synthetic@example.invalid")
        (self.repo / "fixture.txt").write_text("SYNTHETIC_OLD_VALUE\n")
        git("add", "fixture.txt")
        git("commit", "-m", "synthetic first")
        self.first = git("rev-parse", "HEAD")
        (self.repo / "fixture.txt").unlink()
        git("add", "-A")
        git("commit", "-m", "synthetic delete")
        self.head = git("rev-parse", "HEAD")
        git("remote", "add", "origin", scan.EXPECTED_REMOTE)

    def test_pr_range_requires_exact_commits_and_covers_removed_history(self):
        self.assertEqual(scan.range_boundary(self.repo, self.first, self.head), (self.first, 1))
        for base, head in [("bad", self.head), (self.first, "a" * 40), ("b" * 40, self.head), (self.head, self.head)]:
            with self.subTest(base=base), self.assertRaises(scan.ScanError):
                scan.range_boundary(self.repo, base, head)

    def test_history_preflight_and_removed_file(self):
        self.assertEqual(scan.preflight(self.repo), self.head)
        result = subprocess.run(["git", "-C", str(self.repo), "show", self.first + ":fixture.txt"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, "SYNTHETIC_OLD_VALUE\n")
        self.assertFalse((self.repo / "fixture.txt").exists())

    def test_checkout_origin_without_dot_git_is_accepted(self):
        subprocess.run(["git", "-C", str(self.repo), "remote", "set-url", "origin",
                        scan.EXPECTED_REMOTE.removesuffix(".git")], capture_output=True, check=True)
        self.assertEqual(scan.preflight(self.repo), self.head)

    def test_exact_head_and_complete_history_are_bound(self):
        self.assertEqual(scan.preflight(self.repo, self.head), self.head)
        with self.assertRaisesRegex(scan.ScanError, "expected commit"):
            scan.preflight(self.repo, self.first)
        coverage = scan.history_coverage(self.repo)
        self.assertEqual(coverage["reachable_commit_count"], 2)
        self.assertEqual(coverage["root_commit_shas"], [self.first])
        self.assertIn("other_refs", coverage["excluded_scopes"])

    def test_inherited_git_config_cannot_change_the_checkout(self):
        with patch.dict(os.environ, {"GIT_DIR": str(self.root / "absent"),
                                      "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare",
                                      "GIT_CONFIG_VALUE_0": "true"}):
            self.assertEqual(scan.preflight(self.repo, self.head), self.head)

    def test_external_git_configuration_is_rejected(self):
        subprocess.run(["git", "-C", str(self.repo), "config", "core.fsmonitor", "synthetic-command"],
                       capture_output=True, check=True)
        with self.assertRaisesRegex(scan.ScanError, "configuration"):
            scan.preflight(self.repo)

    def test_alternates_and_replacements_are_rejected(self):
        alternate = self.repo / ".git/objects/info/alternates"
        alternate.write_text(str(self.root / "absent") + "\n")
        with self.assertRaisesRegex(scan.ScanError, "history"):
            scan.preflight(self.repo)
        alternate.unlink()
        subprocess.run(["git", "-C", str(self.repo), "replace", self.head, self.first],
                       capture_output=True, check=True)
        with self.assertRaisesRegex(scan.ScanError, "history"):
            scan.preflight(self.repo)

    def test_shallow_clone_is_incomplete(self):
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "--depth", "1", self.repo.as_uri(), str(shallow)],
                       capture_output=True, check=True)
        subprocess.run(["git", "-C", str(shallow), "remote", "set-url", "origin", scan.EXPECTED_REMOTE],
                       capture_output=True, check=True)
        with self.assertRaisesRegex(scan.ScanError, "incomplete"):
            scan.preflight(shallow)

    def test_parser_never_returns_secret_fields(self):
        output = self.root / "output"
        canary = "PRIVATE_SYNTHETIC_CANARY_123"
        output.write_text(json.dumps(finding(self.first, canary)) + "\n")
        result = parse_findings(output, set())
        self.assertEqual(result, {"findings": 1, "suppressed": 0, "needs_review": 1})
        self.assertNotIn(canary, json.dumps(result))

    def test_malformed_output_fails_closed(self):
        output = self.root / "output"
        output.write_text(json.dumps(finding(self.first)) + "\n{" )
        with self.assertRaisesRegex(ScanOutputError, "malformed"):
            parse_findings(output, set())

    def test_completion_record_is_required_and_version_bound(self):
        diagnostics = self.root / "stderr"
        diagnostics.write_bytes(b"")
        with self.assertRaisesRegex(ScanOutputError, "unconfirmed"):
            validate_completion(diagnostics, "3.99.4")
        diagnostics.write_bytes(completion_log("3.99.3"))
        with self.assertRaisesRegex(ScanOutputError, "invalid"):
            validate_completion(diagnostics, "3.99.4")
        diagnostics.write_bytes(completion_log())
        validate_completion(diagnostics, "3.99.4")
        diagnostics.write_bytes(b"Docker runtime notice\n" + completion_log())
        validate_completion(diagnostics, "3.99.4")
        diagnostics.write_bytes(b"{bad json\n" + completion_log())
        with self.assertRaisesRegex(ScanOutputError, "malformed"):
            validate_completion(diagnostics, "3.99.4")

    def test_expiring_exact_suppression_and_duplicate_location(self):
        policy = self.root / "policy.json"
        entry = {"detector": "Test", "commit": self.first, "path": "fixture.txt", "line": 1,
                 "owner": "security-maintainer", "reason": "synthetic fixture", "expires": "2026-10-23"}
        policy.write_text(json.dumps({"schema_version": 1, "suppressions": [entry]}))
        active = load_suppressions(policy, date(2026, 10, 22))
        self.assertEqual(load_suppressions(policy, date(2026, 10, 24)), set())
        output = self.root / "output"
        output.write_text(json.dumps(finding(self.first)) + "\n")
        self.assertEqual(parse_findings(output, active)["suppressed"], 1)
        output.write_text((json.dumps(finding(self.first)) + "\n") * 2)
        self.assertEqual(parse_findings(output, active)["needs_review"], 2)

    def test_scan_command_has_offline_and_no_verification_boundary(self):
        original_run = subprocess.run
        captured = []
        def fake_run(command, *args, **kwargs):
            if command[0] == "docker":
                captured.extend(command)
                if command[1] == "pull":
                    kwargs["stderr"].write(b"Download progress outside scanner diagnostics")
                    return subprocess.CompletedProcess(command, 0)
                kwargs["stdout"].write((json.dumps(finding(self.first)) + "\n").encode())
                kwargs["stderr"].write(completion_log())
                return subprocess.CompletedProcess(command, 183)
            return original_run(command, *args, **kwargs)
        triage = self.root / "private-triage.json"
        with patch.object(scan.subprocess, "run", side_effect=fake_run):
            result = scan.run_scan(self.repo, triage_file=triage)
        self.assertEqual(result["needs_review"], 1)
        self.assertEqual(result["schema_version"], 2)
        self.assertEqual(result["reachable_commit_count"], 2)
        self.assertEqual(result["root_commit_shas"], [self.first])
        self.assertTrue(result["coverage_complete"])
        scan.validate_receipt(result)
        for change in ({"needs_review": 0}, {"unexpected": "PRIVATE_SYNTHETIC_CANARY_123"},
                       {"commit": "not-a-commit"}, {"root_commit_shas": [self.first, self.first]},
                       {"elapsed_seconds": float("nan")}, {"coverage_complete": False}):
            with self.assertRaisesRegex(scan.ScanError, "invalid public scan receipt"):
                scan.validate_receipt({**result, **change})
        for option in ("none", "--no-verification", "--no-update", "--fail-on-scan-errors", "--pull=never"):
            self.assertIn(option, captured)
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY_123", json.dumps(result))
        self.assertEqual(json.loads(triage.read_text())["locations"][0]["commit"], self.first)
        self.assertNotIn("FAKE-TEST-ONLY", triage.read_text())

    def test_scan_failure_does_not_publish_partial_findings(self):
        original_run = subprocess.run
        docker_commands = []
        def fake_run(command, *args, **kwargs):
            if command[0] == "docker":
                docker_commands.append(command[:3])
                if command[1] == "pull":
                    return subprocess.CompletedProcess(command, 0)
                if command[1] == "rm":
                    return subprocess.CompletedProcess(command, 0)
                kwargs["stdout"].write((json.dumps(finding(self.first)) + "\n").encode())
                kwargs["stderr"].write(b"PRIVATE_SYNTHETIC_CANARY_123")
                return subprocess.CompletedProcess(command, 1)
            return original_run(command, *args, **kwargs)
        with patch.object(scan.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(scan.ScanError, "incomplete") as error:
                scan.run_scan(self.repo)
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY_123", str(error.exception))
        self.assertTrue(any(command[:2] == ["docker", "rm"] for command in docker_commands))

    def test_pull_failure_is_safe_and_does_not_start_scan(self):
        original_run = subprocess.run
        def fake_run(command, *args, **kwargs):
            if command[0] == "docker":
                self.assertEqual(command[1], "pull")
                kwargs["stderr"].write(b"PRIVATE_SYNTHETIC_CANARY_123")
                return subprocess.CompletedProcess(command, 1)
            return original_run(command, *args, **kwargs)
        with patch.object(scan.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(scan.ScanError, "image fetch failed") as error:
                scan.run_scan(self.repo)
        self.assertNotIn("PRIVATE_SYNTHETIC_CANARY_123", str(error.exception))

    def test_moved_head_cannot_receive_a_completed_scan_receipt(self):
        original_run = subprocess.run
        def fake_run(command, *args, **kwargs):
            if command[0] == "docker":
                if command[1] == "pull":
                    return subprocess.CompletedProcess(command, 0)
                original_run(["git", "-C", str(self.repo), "commit", "--allow-empty", "-m", "synthetic concurrent change"],
                             capture_output=True, check=True)
                kwargs["stderr"].write(completion_log())
                return subprocess.CompletedProcess(command, 0)
            return original_run(command, *args, **kwargs)
        with patch.object(scan.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(scan.ScanError, "expected commit"):
                scan.run_scan(self.repo, expected_head=self.head)

    @unittest.skipUnless(os.environ.get("WORKFORCE_TRUFFLEHOG_BIN"), "pinned CLI not supplied")
    def test_real_cli_finds_removed_synthetic_private_key(self):
        key = self.repo / "synthetic_test_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       capture_output=True, check=True)
        def git(*args):
            subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, check=True)
        git("add", key.name)
        git("commit", "-m", "synthetic private key")
        key.unlink()
        (self.repo / "synthetic_test_key.pub").unlink()
        git("add", "-A")
        git("commit", "-m", "remove synthetic key")
        result = subprocess.run([
            os.environ["WORKFORCE_TRUFFLEHOG_BIN"], "--no-verification", "--no-update",
            "--no-filter-unverified", "--results=verified,unknown,unverified,filtered_unverified",
            "--json", "--fail", "--fail-on-scan-errors", "git", "file://repo",
            "--branch", "HEAD",
        ], cwd=self.root, capture_output=True, timeout=60, check=False)
        self.assertEqual(result.returncode, 183)
        records = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["DetectorName"], "PrivateKey")
        self.assertEqual(records[0]["SourceMetadata"]["Data"]["Git"]["file"], key.name)
        output = self.root / "pinned-output"
        diagnostics = self.root / "pinned-diagnostics"
        output.write_bytes(result.stdout)
        diagnostics.write_bytes(result.stderr)
        validate_completion(diagnostics, "3.99.4")
        self.assertEqual(parse_findings(output, set())["findings"], 1)

    @unittest.skipUnless(os.environ.get("WORKFORCE_TRUFFLEHOG_CONTAINER"), "Linux container test not requested")
    def test_linux_container_finds_removed_synthetic_private_key(self):
        key = self.repo / "synthetic_test_key"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       capture_output=True, check=True)
        def git(*args):
            subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, check=True)
        git("add", key.name)
        git("commit", "-m", "synthetic private key")
        key.unlink()
        (self.repo / "synthetic_test_key.pub").unlink()
        git("add", "-A")
        git("commit", "-m", "remove synthetic key")
        result = scan.run_scan(self.repo, timeout=120)
        self.assertTrue(result["completed"])
        self.assertEqual(result["scanner"], scan.image_pin()[0])
        self.assertEqual(result["findings"], 1)


if __name__ == "__main__":
    unittest.main()
