"""Tests for netmon/config.py: whole_network_enabled().

Environment wins (backwards compatible with NETMON_WHOLE_NETWORK=1),
then the config file's capture.whole_network. Run:
python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon import config as cfgm


class TestWholeNetworkEnabled(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.pop("NETMON_WHOLE_NETWORK", None)
        self._old_xdg = os.environ.get("XDG_CONFIG_HOME")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["XDG_CONFIG_HOME"] = self._tmp.name
        cfgm._CACHE.clear()

    def tearDown(self):
        if self._old_env is None:
            os.environ.pop("NETMON_WHOLE_NETWORK", None)
        else:
            os.environ["NETMON_WHOLE_NETWORK"] = self._old_env
        if self._old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self._old_xdg
        cfgm._CACHE.clear()
        self._tmp.cleanup()

    def _write_config(self, whole_network):
        d = Path(self._tmp.name) / "brutedash"
        d.mkdir(parents=True, exist_ok=True)
        (d / "config.yaml").write_text(
            f"capture:\n  whole_network: {str(whole_network).lower()}\n")

    def test_env_truthy_values(self):
        for val in ("1", "true", "yes", "on", "TRUE", " 1 "):
            os.environ["NETMON_WHOLE_NETWORK"] = val
            self.assertTrue(cfgm.whole_network_enabled(), val)

    def test_env_falsy_values(self):
        for val in ("0", "false", "no", "off", "banana"):
            os.environ["NETMON_WHOLE_NETWORK"] = val
            self.assertFalse(cfgm.whole_network_enabled(), val)

    def test_env_wins_over_config(self):
        self._write_config(True)
        os.environ["NETMON_WHOLE_NETWORK"] = "0"
        self.assertFalse(cfgm.whole_network_enabled())

    def test_config_true_when_env_unset(self):
        self._write_config(True)
        self.assertTrue(cfgm.whole_network_enabled())

    def test_config_false_when_env_unset(self):
        self._write_config(False)
        self.assertFalse(cfgm.whole_network_enabled())

    def test_missing_config_defaults_false(self):
        # No config.yaml at all -> safe default.
        self.assertFalse(cfgm.whole_network_enabled())


if __name__ == "__main__":
    unittest.main()
