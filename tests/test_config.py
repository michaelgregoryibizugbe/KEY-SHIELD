"""Tests for configuration system."""

import os
import unittest
from keyshield.core.config import Config, get_config, PROFILES


class TestConfig(unittest.TestCase):

    def test_config_singleton(self):
        c1 = get_config()
        c2 = get_config()
        self.assertIs(c1, c2)

    def test_default_whitelist_not_empty(self):
        config = get_config()
        self.assertTrue(len(config.whitelist) > 20)

    def test_whitelist_check(self):
        config = get_config()
        self.assertTrue(config.is_whitelisted("systemd"))
        self.assertTrue(config.is_whitelisted("SYSTEMD"))  # case insensitive
        self.assertFalse(config.is_whitelisted("xyznotreal"))

    def test_self_exclusion(self):
        config = get_config()
        self.assertTrue(config.is_own_pid(os.getpid()))
        self.assertFalse(config.is_own_pid(99999999))

    def test_should_skip(self):
        config = get_config()
        self.assertTrue(config.should_skip(os.getpid(), "keyshield"))
        self.assertTrue(config.should_skip(0, "system"))
        self.assertTrue(config.should_skip(1, "init"))

    def test_profiles_exist(self):
        self.assertIn("quick", PROFILES)
        self.assertIn("standard", PROFILES)
        self.assertIn("paranoid", PROFILES)

    def test_set_profile(self):
        config = get_config()
        config.set_profile("paranoid")
        self.assertEqual(config.profile.name, "paranoid")
        self.assertEqual(config.profile.cpu_anomaly_threshold, 15.0)
        config.set_profile("standard")  # Reset

    def test_to_dict(self):
        config = get_config()
        d = config.to_dict()
        self.assertIn("profile", d)
        self.assertIn("whitelist_count", d)
        self.assertIn("own_pids", d)


if __name__ == "__main__":
    unittest.main()
