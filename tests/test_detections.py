import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from automation.cloudtrail_detections import suspicious_key_use  # noqa: E402
from automation.common import load_jsonl  # noqa: E402
from automation.enrich_ip import enrich, load_blocklist  # noqa: E402
from automation.okta_detections import impossible_travel, mfa_fatigue  # noqa: E402
from automation.windows_detections import detect_bruteforce  # noqa: E402

DATA = ROOT / "data/sample"


class DetectionTests(unittest.TestCase):
    def test_bruteforce_then_success(self):
        alerts = detect_bruteforce(load_jsonl(DATA / "windows_security.json"))
        self.assertEqual(len(alerts), 1)
        a = alerts[0]
        self.assertEqual(a["source_ip"], "203.0.113.45")
        self.assertTrue(a["success_after_failures"])
        self.assertEqual(a["compromised_account"], "admin.svc")
        self.assertEqual(a["severity"], "high")
        self.assertGreaterEqual(len(a["follow_on_activity"]), 3)

    def test_no_bruteforce_alert_on_normal_typos(self):
        clean = [e for e in load_jsonl(DATA / "windows_security.json")
                 if e.get("IpAddress") != "203.0.113.45"]
        self.assertEqual(detect_bruteforce(clean), [])

    def test_impossible_travel(self):
        alerts = impossible_travel(load_jsonl(DATA / "okta_system.json"))
        self.assertEqual([a["user"] for a in alerts], ["asha.k@example.com"])
        self.assertGreater(alerts[0]["required_speed_kmh"], 900)

    def test_mfa_fatigue(self):
        alerts = mfa_fatigue(load_jsonl(DATA / "okta_system.json"))
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0]["mfa_success_afterwards"])

    def test_leaked_key(self):
        alerts = suspicious_key_use(load_jsonl(DATA / "cloudtrail.json"))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "203.0.113.77")
        self.assertIn("AttachUserPolicy", alerts[0]["sensitive_actions"])

    def test_enrichment(self):
        bl = load_blocklist(ROOT / "data/threat_intel/blocklist.csv")
        self.assertEqual(enrich("10.10.1.5", bl)["verdict"], "internal")
        self.assertEqual(enrich("203.0.113.45", bl)["verdict"], "listed-malicious")
        self.assertEqual(enrich("192.0.2.77", bl)["verdict"], "external-unknown")


if __name__ == "__main__":
    unittest.main()
