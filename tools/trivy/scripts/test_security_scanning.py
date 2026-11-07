import hashlib
from datetime import date
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import security_scan as scan
import security_scope as scope


class SecurityTests(unittest.TestCase):
    def test_image_scan_omits_fs_only_dev_dependency_flag(self):
        image = scan.vulnerability_scan_arguments("image", [], Path("report.json"), "sha256:abc")
        source = scan.vulnerability_scan_arguments("fs", [], Path("report.json"), "source")
        self.assertNotIn("--include-dev-deps", image)
        self.assertIn("--include-dev-deps", source)

    def test_existing_iac_baseline_is_exact_counted_and_expires(self):
        item = {"id": "AZU-0012", "target": "infra/modules/storage/main.tf",
                "resource": "module.storage", "severity": "HIGH"}
        baseline = {"schemaVersion": 1, "owner": "test", "reason": "test", "expiresUtc": "2026-11-01",
                    "findings": [{k: item[k] for k in ("id", "target", "resource")}]}
        self.assertEqual(([], [item]), scan.classify_existing_iac([item], baseline, date(2026, 10, 12)))
        self.assertEqual(([item], [item]), scan.classify_existing_iac([item, item], baseline, date(2026, 10, 12)))
        changed = {**item, "resource": "module.storage_new"}
        self.assertEqual(([changed], []), scan.classify_existing_iac([changed], baseline, date(2026, 10, 12)))
        with self.assertRaisesRegex(ValueError, "expired"):
            scan.classify_existing_iac([item], baseline, date(2026, 11, 1))

    def test_exceptions_are_exact_scoped_and_expire(self):
        finding = {"target": "apps/api/package-lock.json", "id": "CVE-test", "package": "test", "installed": "1", "resource": None}
        exception = {**finding, "scope": "source", "owner": "test-owner", "reason": "Test fixture", "expires": "2026-11-01"}
        today = date(2026, 10, 11)
        self.assertEqual(([], [finding]), scan.apply_exceptions([finding], [exception], "source", today))
        self.assertEqual(([finding], []), scan.apply_exceptions([finding], [exception], "image", today))
        other = {**finding, "installed": "2"}
        self.assertEqual(([other], []), scan.apply_exceptions([other], [exception], "source", today))
        with self.assertRaisesRegex(ValueError, "Expired"):
            scan.apply_exceptions([finding], [exception], "source", date(2026, 11, 1))
        with self.assertRaises(ValueError):
            scan.apply_exceptions([finding], [{**exception, "reason": ""}], "source", today)

    def test_gate_blocks_fixable_high_and_critical_only(self):
        findings = [
            {"Severity": "HIGH", "FixedVersion": "2", "VulnerabilityID": "high"},
            {"Severity": "CRITICAL", "FixedVersion": "2", "VulnerabilityID": "critical"},
            {"Severity": "HIGH", "VulnerabilityID": "unfixed"},
            {"Severity": "MEDIUM", "FixedVersion": "2", "VulnerabilityID": "medium"}]
        report = {"Results": [{"Vulnerabilities": findings}]}
        self.assertEqual(["high", "critical"], [x["id"] for x in scan.gate_findings(report, "vuln")])
        # Filtering must not erase unfixed or lower-severity findings in the raw report.
        self.assertEqual(4, len(report["Results"][0]["Vulnerabilities"]))

    def test_gate_only_blocks_failed_configurations(self):
        report = {"Results": [{"Misconfigurations": [
            {"Severity": "HIGH", "Status": "FAIL", "ID": "bad"},
            {"Severity": "HIGH", "Status": "PASS", "ID": "good"},
            {"Severity": "LOW", "Status": "FAIL", "ID": "low"}]}]}
        self.assertEqual(["bad"], [x["id"] for x in scan.gate_findings(report, "misconfig")])
        with self.assertRaises(ValueError):
            scan.gate_findings({"Results": [{"Vulnerabilities": [{}]}]}, "vuln")

    def test_docs_skip_but_unknown_diff_scans_everything(self):
        self.assertEqual((False, []), scope.select(["docs/backlog.md", "README.md"]))
        self.assertEqual(10, len(scope.select([])[1]))
        self.assertEqual(10, len(scope.select(["new-shared-config.json"])[1]))
        self.assertEqual(10, len(scope.select(["../outside"])[1]))

    def test_image_dependencies_include_shared_manifests(self):
        self.assertEqual({"sam-ttpl", "fowler-connection", "fowler-retrieval", "relias"},
                         set(scope.select(["apps/api/package-lock.json"])[1]))
        self.assertEqual(["provider"], scope.select(["apps/provider-importer/src/session.mjs"])[1])
        self.assertEqual([], scope.select(["apps/web/src/App.tsx"])[1])
        with self.assertRaises(ValueError):
            scope.select(["apps/new-worker/Dockerfile"])


    def test_staging_excludes_personal_files_credentials_and_state(self):
        for path in ["docs/roster.json", ".agents/evidence/package-lock.json", "infra/prod.tfstate",
                     "infra/secret.tfvars", "apps/web/.env", "apps/api/person.pdf"]:
            self.assertFalse(scan.scan_input(Path(path)))
        self.assertTrue(scan.scan_input(Path("infra/modules/sql/main.tf")))
        self.assertTrue(scan.scan_input(Path("scripts/fowler/Retrieval.Dockerfile")))

    def test_staging_uses_tracked_allowlist_and_rejects_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "repo"
            source.mkdir()
            (source / "apps").mkdir()
            (source / "apps/package-lock.json").write_text("{}")
            (source / "apps/private.txt").write_text("not a scan input")
            with patch.object(scan.subprocess, "check_output", return_value=b"apps/package-lock.json\0apps/private.txt\0"):
                self.assertEqual(["apps/package-lock.json"], scan.stage_source(source, root / "stage"))
            with patch.object(scan.subprocess, "check_output", return_value=b"apps/../../package-lock.json\0"):
                with self.assertRaises(ValueError):
                    scan.stage_source(source, root / "other")

    def test_empty_or_corrupt_results_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "result.json"
            for value in ({}, {"SchemaVersion": 2}, {"SchemaVersion": 2, "Results": []}):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    scan.validate_report(path, "vuln")
            path.write_text(json.dumps({"SchemaVersion": 2, "Results": [{"Packages": [{"Name": "test"}]}]}))
            scan.validate_report(path, "vuln")

    def test_bad_checksum_does_not_extract_or_run(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(scan.platform, "system", return_value="Windows"), \
                 patch.object(scan.platform, "machine", return_value="AMD64"), \
                 patch.object(scan.urllib.request, "urlopen", return_value=io.BytesIO(b"tampered")):
                with self.assertRaisesRegex(ValueError, "checksum"):
                    scan.install(Path(folder) / "tools")
                self.assertFalse((Path(folder) / "tools").exists())

    def test_installer_only_extracts_expected_executable(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("trivy.exe", b"fixture")
            archive.writestr("../escape", b"do not extract")
        payload = data.getvalue()
        spec = {"trivy": {"version": "test", "windows": {"archive": "test.zip", "sha256": hashlib.sha256(payload).hexdigest()}}}
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(scan.platform, "system", return_value="Windows"), \
                 patch.object(scan.platform, "machine", return_value="AMD64"), \
                 patch.object(scan.urllib.request, "urlopen", return_value=io.BytesIO(payload)), \
                 patch.object(scan.json, "loads", return_value=spec):
                scan.install(Path(folder) / "tools")
            self.assertEqual(b"fixture", (Path(folder) / "tools/trivy.exe").read_bytes())
            self.assertFalse((Path(folder) / "escape").exists())


if __name__ == "__main__":
    unittest.main()
