from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tspace_scan.license_classifier import LicenseClassifier
from tspace_scan.models import DigitalSignatureInfo, PolicyRule, SoftwareItem
from tspace_scan.risk_analyzer import RiskAnalyzer, risk_level_from_score
from tspace_scan.app_classifier import classify_app


class LicenseClassifierTests(unittest.TestCase):
    def test_known_open_source_software(self) -> None:
        item = SoftwareItem(name="7-Zip 24.09", publisher="Igor Pavlov")
        LicenseClassifier().classify(item)
        self.assertEqual(item.license_type, "Open-source software")
        self.assertGreaterEqual(item.license_confidence, 80)

    def test_unknown_when_no_reliable_signal(self) -> None:
        item = SoftwareItem(name="Internal Tool")
        LicenseClassifier().classify(item)
        self.assertEqual(item.license_type, "Unknown")

    def test_python_is_open_source(self) -> None:
        item = SoftwareItem(name="Python 3.14.3", publisher="Python Software Foundation")
        LicenseClassifier().classify(item)
        self.assertEqual(item.license_type, "Open-source software")


class RiskAnalyzerTests(unittest.TestCase):
    def test_keyword_finding_raises_score(self) -> None:
        item = SoftwareItem(name="Example", install_location=r"C:\Tools\Example crack")
        RiskAnalyzer().analyze(item)
        self.assertGreaterEqual(item.risk_score, 20)
        self.assertTrue(item.risk_findings)

    def test_risk_level_thresholds(self) -> None:
        self.assertEqual(risk_level_from_score(0), "Low Risk")
        self.assertEqual(risk_level_from_score(35), "Medium Risk")
        self.assertEqual(risk_level_from_score(70), "High Risk")
        self.assertEqual(risk_level_from_score(90), "Critical Risk")

    def test_blacklist_policy_raises_high_risk(self) -> None:
        item = SoftwareItem(name="Blocked App")
        analyzer = RiskAnalyzer(blacklist=[PolicyRule(match_type="name", pattern="blocked", risk_level="High Risk")])
        analyzer.analyze(item)
        self.assertEqual(item.risk_level, "High Risk")
        self.assertTrue(any(finding.signal == "blacklist_policy" for finding in item.risk_findings))

    def test_whitelist_policy_suppresses_risk(self) -> None:
        item = SoftwareItem(name="Blocked App crack")
        analyzer = RiskAnalyzer(whitelist=[PolicyRule(match_type="name", pattern="blocked app")])
        analyzer.analyze(item)
        self.assertEqual(item.risk_score, 0)
        self.assertTrue(any(finding.signal == "whitelist" for finding in item.risk_findings))

    def test_invalid_signature_on_commercial_software_adds_signal(self) -> None:
        item = SoftwareItem(
            name="Adobe Example",
            publisher="Adobe",
            executable_path=r"C:\Program Files\Adobe\Example\example.exe",
            license_type="Subscription-based",
            signature=DigitalSignatureInfo(status="HashMismatch"),
        )
        RiskAnalyzer().analyze(item)
        self.assertTrue(any(finding.signal == "invalid_digital_signature" for finding in item.risk_findings))

    def test_medium_keyword_ignored_for_driver_context(self) -> None:
        item = SoftwareItem(
            name="NVIDIA Graphics Driver",
            publisher="NVIDIA",
            install_location=r"C:\Program Files\NVIDIA Corporation\loader\serial",
            license_type="Freeware",
        )
        classify_app(item)
        RiskAnalyzer().analyze(item)
        self.assertEqual(item.risk_score, 0)


class AppClassifierTests(unittest.TestCase):
    def test_office_is_license_relevant(self) -> None:
        item = SoftwareItem(name="Microsoft 365 Apps for business - en-us")
        classify_app(item)
        self.assertEqual(item.app_group, "License relevant")
        self.assertEqual(item.app_category, "Office/Productivity")

    def test_nvidia_is_driver_group(self) -> None:
        item = SoftwareItem(name="NVIDIA Graphics Driver")
        classify_app(item)
        self.assertEqual(item.app_group, "Driver/Hardware")
        self.assertFalse(item.is_license_relevant)


if __name__ == "__main__":
    unittest.main()
