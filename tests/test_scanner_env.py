"""Scanner subprocess environment tests (security S4, 2026-11-09).

The nuclei and amass binaries are downloaded from the internet; their
subprocesses must never inherit brutedash's secrets (OPENAI_API_KEY,
ABUSEIPDB_API_KEY, NETMON_SMTP_PASS, BRUTEDASH_AUTH_* passwords).
These tests pin the WHOLE environment object handed to subprocess.run
at all four call sites (version probe + scan, both modules): the
scrubbed env is exactly os.environ minus secret-named vars -- nothing
else is dropped or added.
"""
import os
import shutil
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon import amass as amassm
from netmon import nuclei as nucleim
from netmon.envscrub import is_secret_name, scrubbed_env

KNOWN_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/tester",
    "SystemRoot": "C:/Windows",
    "PLAIN_VAR": "keepme",
    "OPENAI_API_KEY": "sk-sentinel",
    "ABUSEIPDB_API_KEY": "abuse-sentinel",
    "NETMON_SMTP_PASS": "smtp-sentinel",
    "BRUTEDASH_AUTH_OWNER_PASSWORD": "owner-sentinel",
    "MY_TOKEN": "token-sentinel",
    "APP_SECRET": "secret-sentinel",
    "lowercase_api_key": "lower-sentinel",
}
EXPECTED_ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/tester",
    "SystemRoot": "C:/Windows",
    "PLAIN_VAR": "keepme",
}


class ScrubbedEnvTests(unittest.TestCase):
    def test_exact_environment(self):
        with mock.patch.dict(os.environ, KNOWN_ENV, clear=True):
            self.assertEqual(scrubbed_env(), EXPECTED_ENV)

    def test_secret_name_markers(self):
        for name in ("OPENAI_API_KEY", "MY_TOKEN", "APP_SECRET",
                     "DB_PASSWORD", "SMTP_PASS", "passwd_file",
                     "monkey_business"):  # contains KEY -- over-scrub ok
            self.assertTrue(is_secret_name(name), name)
        for name in ("PATH", "HOME", "SystemRoot", "LANG",
                     "BRUTEDASH_HOME", "NETMON_WHOLE_NETWORK"):
            self.assertFalse(is_secret_name(name), name)

    def test_real_environ_secrets_removed_rest_kept(self):
        with mock.patch.dict(os.environ,
                             {"ZZ_SENTINEL_API_KEY": "x",
                              "ZZ_SENTINEL_PLAIN": "y"}):
            env = scrubbed_env()
        self.assertNotIn("ZZ_SENTINEL_API_KEY", env)
        self.assertEqual(env["ZZ_SENTINEL_PLAIN"], "y")


class NucleiEnvTests(unittest.TestCase):
    def test_version_probe_env_scrubbed(self):
        with mock.patch.dict(os.environ, KNOWN_ENV, clear=True), \
             mock.patch("netmon.nuclei.find_binary",
                        return_value="/usr/bin/nuclei"), \
             mock.patch("subprocess.run") as sr:
            sr.return_value = mock.Mock(stdout="v3.3.9", stderr="")
            nucleim.binary_version()
        self.assertEqual(sr.call_args.kwargs["env"], EXPECTED_ENV)

    def test_scan_env_scrubbed(self):
        with mock.patch.dict(os.environ, KNOWN_ENV, clear=True), \
             mock.patch("netmon.nuclei.find_binary",
                        return_value="/usr/bin/nuclei"), \
             mock.patch("subprocess.run") as sr:
            sr.return_value = mock.Mock(stdout="", stderr="")
            res = nucleim.run_scan(["192.168.1.10"])
        self.assertEqual(sr.call_args.kwargs["env"], EXPECTED_ENV)
        shutil.rmtree(res.get("work_dir", ""), ignore_errors=True)


class AmassEnvTests(unittest.TestCase):
    def test_version_probe_env_scrubbed(self):
        with mock.patch.dict(os.environ, KNOWN_ENV, clear=True), \
             mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"), \
             mock.patch("subprocess.run") as sr:
            sr.return_value = mock.Mock(stdout="v4.2.0", stderr="")
            amassm.binary_version()
        self.assertEqual(sr.call_args.kwargs["env"], EXPECTED_ENV)

    def test_enum_env_scrubbed(self):
        with mock.patch.dict(os.environ, KNOWN_ENV, clear=True), \
             mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"), \
             mock.patch("netmon.amass.binary_version",
                        return_value="v4.2.0"), \
             mock.patch("subprocess.run") as sr, \
             mock.patch("os.path.exists", return_value=True):
            sr.return_value = mock.Mock(stdout="", stderr="")
            res = amassm.run_enum("example.com")
        self.assertTrue(res["ok"])
        self.assertEqual(sr.call_args.kwargs["env"], EXPECTED_ENV)
        shutil.rmtree(res.get("work_dir", ""), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
