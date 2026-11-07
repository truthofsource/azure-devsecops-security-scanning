import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zap_authenticated as zap


class ZapContractTests(unittest.TestCase):
    def test_summary_discards_sensitive_fields_and_counts_fixed_metadata_only(self):
        canary = "PRIVATE_TOKEN_AND_PERSON_CANARY"
        result = zap.alert_counts([{"pluginId": "10038", "riskcode": "2", "url": canary, "evidence": canary, "requestHeader": canary}])
        self.assertEqual(result, [{"ruleId": "10038", "risk": 2, "count": 1}])
        self.assertNotIn(canary, json.dumps(result))
        self.assertEqual(zap.alert_counts([{"pluginId": "10038", "risk": "Medium"}]),
                         [{"ruleId": "10038", "risk": 2, "count": 1}])
        with self.assertRaises(ValueError):
            zap.alert_counts([{"pluginId": "10038", "risk": "Low", "riskcode": "3"}])
        for row in [{"pluginId": canary, "riskcode": "2"}, {"pluginId": "10038", "riskcode": "unknown"}]:
            with self.assertRaises(ValueError):
                zap.alert_counts([row])

    def test_real_immutable_pin_and_fixed_nonproduction_target(self):
        self.assertRegex(zap.image_pin(), r"^ghcr.io/zaproxy/zaproxy@sha256:[a-f0-9]{64}$")
        self.assertEqual(zap.API, "https://api.workforce.invalid")
        source = Path(zap.__file__).read_text(encoding="utf-8")
        self.assertNotIn("spider/action/scan", source)
        self.assertNotIn("ascan/action/scan", source)
        self.assertIn('followRedirects="false"', source)
        self.assertIn('headers={"Host": "zap"}', source)

    def test_missing_or_repository_token_file_is_rejected_before_any_container(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(zap.subprocess, "run") as docker:
            with self.assertRaises(ValueError):
                zap.run(Path(folder) / "missing", "a" * 36, Path(folder) / "summary.json")
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
