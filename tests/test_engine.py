"""Tests for v3.0 engine."""

import unittest
from keyshield.core.engine import ScanEngine, ScanResult, Finding
from keyshield.core.threat_db import ThreatLevel, ThreatCategory
from keyshield.core.config import Config, get_config


class TestScanResult(unittest.TestCase):
    def test_empty_is_clean(self):
        r = ScanResult()
        r.calculate_stats()
        self.assertEqual(r.overall_risk, ThreatLevel.CLEAN)

    def test_critical_sets_critical(self):
        r = ScanResult()
        r.findings.append(Finding(
            detector="t", category=ThreatCategory.KEYLOGGER,
            level=ThreatLevel.CRITICAL, title="T", description="D",
        ))
        r.calculate_stats()
        self.assertEqual(r.overall_risk, ThreatLevel.CRITICAL)

    def test_dedup(self):
        r = ScanResult()
        f = Finding(detector="a", category=ThreatCategory.KEYLOGGER,
                    level=ThreatLevel.HIGH, title="Same", description="D", pid=123)
        r.findings.extend([f, f])
        self.assertEqual(len(r.findings), 2)


class TestConfig(unittest.TestCase):
    def test_self_exclusion(self):
        import os
        config = get_config()
        self.assertTrue(config.is_own_pid(os.getpid()))

    def test_whitelist(self):
        config = get_config()
        self.assertTrue(config.is_whitelisted("systemd"))
        self.assertFalse(config.is_whitelisted("definitely_not_whitelisted_xyz"))


class TestScanEngine(unittest.TestCase):
    def test_init(self):
        engine = ScanEngine()
        self.assertTrue(len(engine.detectors) >= 9)

    def test_quick_scan(self):
        engine = ScanEngine()
        result = engine.run_scan(quick=True)
        self.assertIsInstance(result, ScanResult)
        self.assertTrue(len(result.detectors_run) > 0)


if __name__ == "__main__":
    unittest.main()
