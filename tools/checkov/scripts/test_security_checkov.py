import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import security_checkov as checkov


def fixture():
    return {"check_type": "terraform", "summary": {"passed": 0, "failed": 1, "skipped": 0,
            "parsing_errors": 0, "resource_count": 1, "checkov_version": "test"},
            "results": {"passed_checks": [], "skipped_checks": [], "parsing_errors": [],
                        "failed_checks": [{"check_id": "CKV_AZURE_TEST", "resource": "azurerm_test.example",
                                           "file_path": "/platform/production/main.tf"}]}}


class CheckovFoundationTests(unittest.TestCase):
    def test_findings_are_visible_and_advisory(self):
        data = fixture()
        self.assertEqual(1, checkov.validate_report(data, "test")["failed"])
        self.assertEqual(1, checkov.validate_report([data], "test")["failed"])
        self.assertEqual(1, len(data["results"]["failed_checks"]))

    def test_malformed_empty_wrong_framework_and_wrong_version_fail(self):
        for bad in ({}, [], [fixture(), fixture()], {**fixture(), "check_type": "secrets"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                checkov.validate_report(bad, "test")
        with self.assertRaisesRegex(ValueError, "version"):
            checkov.validate_report(fixture(), "different")

    def test_parse_failures_cannot_be_called_complete(self):
        for field in ("summary", "results"):
            data = fixture()
            data[field]["parsing_errors"] = 1 if field == "summary" else ["broken.tf"]
            with self.assertRaisesRegex(ValueError, "parsing"):
                checkov.validate_report(data, "test")

    def test_counts_and_inventory_must_be_real(self):
        for field, value in (("failed", 0), ("failed", True), ("passed", -1), ("resource_count", 0)):
            data = fixture(); data["summary"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                checkov.validate_report(data, "test")
        data = fixture(); data["results"]["failed_checks"] = [{}]
        with self.assertRaisesRegex(ValueError, "Malformed"):
            checkov.validate_report(data, "test")

    def test_all_skipped_is_not_acceptance(self):
        data = fixture()
        data["results"]["skipped_checks"] = data["results"]["failed_checks"]
        data["results"]["failed_checks"] = []
        data["summary"].update(failed=0, skipped=1)
        with self.assertRaisesRegex(ValueError, "No evaluated"):
            checkov.validate_report(data, "test")

    def test_only_tracked_tf_staged_and_content_hashed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / "repo"; source.mkdir()
            (source / "infra").mkdir(); (source / "infra/main.tf").write_text("resource test")
            names = b"infra/main.tf\0infra/secret.tfvars\0infra/state.tfstate\0docs/private.pdf\0"
            with patch.object(checkov.subprocess, "check_output", return_value=names):
                manifest = checkov.stage_terraform(source, root / "staged")
            self.assertEqual(["infra/main.tf"], list(manifest))
            self.assertEqual(64, len(manifest["infra/main.tf"]))
            with patch.object(checkov.subprocess, "check_output", return_value=b"infra/../../escape.tf\0"):
                with self.assertRaises(ValueError):
                    checkov.stage_terraform(source, root / "other")

    def test_empty_inventory_fails(self):
        with patch.object(checkov.subprocess, "check_output", return_value=b"docs/README.md\0"):
            with self.assertRaisesRegex(ValueError, "No tracked"):
                checkov.stage_terraform(Path("."), Path("unused"))

    def test_scanner_environment_drops_credentials_and_policy_overrides(self):
        with patch.dict(os.environ, {"BC_API_KEY": "fixture", "AZURE_CLIENT_SECRET": "fixture",
                                     "CKV_SKIP_CHECK": "*", "PATH": "tools"}, clear=True):
            env = checkov.scanner_environment(Path("temp"))
        self.assertNotIn("BC_API_KEY", env)
        self.assertNotIn("AZURE_CLIENT_SECRET", env)
        self.assertNotIn("CKV_SKIP_CHECK", env)
        self.assertEqual("tools", env["PATH"])

    def test_nonzero_cli_exit_never_writes_success_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "results"
            with patch.object(checkov, "expected_version", return_value="test"), \
                 patch.object(checkov, "stage_terraform", return_value={"infra/main.tf": "hash"}), \
                 patch.object(checkov.subprocess, "check_output", return_value="test"), \
                 patch.object(checkov.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)):
                with self.assertRaisesRegex(RuntimeError, "execution failed"):
                    checkov.run(Path("checkov"), Path(folder), output)
            self.assertFalse((output / "scan.json").exists())

    def test_success_receipt_explicitly_is_not_security_gate(self):
        def execute(arguments, **kwargs):
            self.assertEqual(str(Path(folder) / "checkov"), arguments[1])
            kwargs["stdout"].write(json.dumps(fixture()))
            return subprocess.CompletedProcess(arguments, 0)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "results"
            with patch.object(checkov, "expected_version", return_value="test"), \
                 patch.object(checkov, "stage_terraform", return_value={"infra/main.tf": "hash"}), \
                 patch.object(checkov.subprocess, "check_output", side_effect=["test", "a" * 40, b""]), \
                 patch.object(checkov.subprocess, "run", side_effect=execute):
                checkov.run(Path(folder) / "python.exe", Path(folder), output, module=True)
            receipt = json.loads((output / "scan.json").read_text())
            self.assertIs(receipt["securityGate"], False)
            self.assertEqual(1, receipt["counts"]["failed"])
            with self.assertRaisesRegex(ValueError, "empty output"):
                checkov.run(Path("checkov"), Path(folder), output)


if __name__ == "__main__":
    unittest.main()
