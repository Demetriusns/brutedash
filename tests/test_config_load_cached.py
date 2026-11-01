"""Tests for netmon/config.py load_cached() env invalidation (2026-11-01).

Bug (head find 2026-10-25, council batch 2026-11-01): load_cached()
keyed its cache on the config file's mtime only, but load() bakes the
current BRUTEDASH_* env vars into the result via _apply_env(). So a
var set/changed after the first load had no effect, and a REMOVED var
kept its old value in force -- including
BRUTEDASH_AUTH_OWNER_PASSWORD. Fix: the cache entry also carries a
fingerprint of the BRUTEDASH_* env; a hit requires both to match.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon import config as cfgm

PORT_VAR = "BRUTEDASH_DASHBOARD_PORT"
PW_VAR = "BRUTEDASH_AUTH_OWNER_PASSWORD"


class TestLoadCachedEnvInvalidation(unittest.TestCase):
    def setUp(self):
        self._saved_env = {k: v for k, v in os.environ.items()
                           if k.startswith("BRUTEDASH_")}
        for k in list(os.environ):
            if k.startswith("BRUTEDASH_"):
                del os.environ[k]
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "config.yaml"
        self.path.write_text("dashboard:\n  port: 5001\n")
        cfgm._CACHE.clear()

    def tearDown(self):
        for k in list(os.environ):
            if k.startswith("BRUTEDASH_"):
                del os.environ[k]
        os.environ.update(self._saved_env)
        cfgm._CACHE.clear()
        self._tmp.cleanup()

    def _port(self):
        return cfgm.get(cfgm.load_cached(self.path), "dashboard.port")

    def test_env_set_after_first_load_takes_effect(self):
        self.assertEqual(self._port(), 5001)
        os.environ[PORT_VAR] = "9090"
        self.assertEqual(self._port(), 9090)

    def test_env_change_takes_effect(self):
        os.environ[PORT_VAR] = "9090"
        self.assertEqual(self._port(), 9090)
        os.environ[PORT_VAR] = "7070"
        self.assertEqual(self._port(), 7070)

    def test_env_removal_reverts_to_file_value(self):
        os.environ[PORT_VAR] = "9090"
        self.assertEqual(self._port(), 9090)
        del os.environ[PORT_VAR]
        self.assertEqual(self._port(), 5001)

    def test_removed_auth_password_does_not_linger_in_cache(self):
        os.environ[PW_VAR] = "demo-pw"
        cfg = cfgm.load_cached(self.path)
        self.assertEqual(cfgm.get(cfg, "auth.owner_password"), "demo-pw")
        del os.environ[PW_VAR]
        cfg = cfgm.load_cached(self.path)
        self.assertEqual(cfgm.get(cfg, "auth.owner_password"), "")

    def test_unchanged_env_and_file_returns_same_cached_object(self):
        first = cfgm.load_cached(self.path)
        self.assertIs(cfgm.load_cached(self.path), first)

    def test_unrelated_env_change_does_not_invalidate(self):
        # Only BRUTEDASH_* vars feed _apply_env, so only they are in the
        # fingerprint; any other env change must keep the cache hit.
        first = cfgm.load_cached(self.path)
        os.environ["SOME_UNRELATED_VAR_XYZ"] = "1"
        try:
            self.assertIs(cfgm.load_cached(self.path), first)
        finally:
            del os.environ["SOME_UNRELATED_VAR_XYZ"]

    def test_mtime_change_still_invalidates(self):
        first = cfgm.load_cached(self.path)
        self.path.write_text("dashboard:\n  port: 6001\n")
        future = time.time() + 5
        os.utime(self.path, (future, future))
        second = cfgm.load_cached(self.path)
        self.assertIsNot(second, first)
        self.assertEqual(cfgm.get(second, "dashboard.port"), 6001)


if __name__ == "__main__":
    unittest.main()
