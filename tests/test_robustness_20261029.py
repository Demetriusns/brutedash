"""Robustness M3 (2026-10-29): health.py unguarded paths.

From council review 2026-10-25, re-verified in source 2026-10-29:

- setup_logging() built its RotatingFileHandler OUTSIDE the OSError
  guard (a construction failure broke startup, contradicting the
  "logging must never break startup" contract) and built a NEW handler
  on every call, discarding it unclosed when one was already installed
  -- FileHandler opens the file at construction, so repeat calls
  leaked an open handle each.
- write_diagnostics_bundle() sections 1 (summary) and 5 (threads) had
  no guard of their own: a summary write failure aborted the whole
  bundle via the outer handler.
- Bundle section 4 only reached conn.close() on the happy path, so
  the diagnostics sqlite handle leaked on the error path.

Council gate 2026-10-29: research APPLY + innovation APPLY (quorum);
innovation's condition adopted -- a swallowed handler failure now
leaves a one-line stderr note instead of silence.

Run: python -m unittest discover -s tests
"""
import io
import logging
import logging.handlers
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

from netmon import config as cfgm
from netmon import health as hm


class _RootHandlersGuard(unittest.TestCase):
    """setup_logging mutates the ROOT logger: save/restore it exactly."""

    def setUp(self):
        self._saved_handlers = logging.getLogger().handlers[:]
        self._saved_level = logging.getLogger().level
        for h in self._saved_handlers:
            logging.getLogger().removeHandler(h)
        self._tmp = tempfile.TemporaryDirectory()
        self._cfg_patch = mock.patch.object(
            cfgm, "config_dir", return_value=Path(self._tmp.name))
        self._cfg_patch.start()

    def tearDown(self):
        self._cfg_patch.stop()
        root = logging.getLogger()
        for h in root.handlers[:]:
            root.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
        for h in self._saved_handlers:
            root.addHandler(h)
        root.setLevel(self._saved_level)
        self._tmp.cleanup()

    def _rfh_count(self):
        return sum(isinstance(h, logging.handlers.RotatingFileHandler)
                   for h in logging.getLogger().handlers)


class SetupLoggingTests(_RootHandlersGuard):

    def test_repeat_calls_install_one_handler_and_construct_one(self):
        real = logging.handlers.RotatingFileHandler
        built = []

        class CountingRFH(real):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                built.append(self)

        with mock.patch.object(logging.handlers, "RotatingFileHandler",
                               CountingRFH):
            hm.setup_logging()
            hm.setup_logging()
            hm.setup_logging()
        self.assertEqual(self._rfh_count(), 1)
        # Pre-fix code constructed (and leaked) a handler per call.
        self.assertEqual(len(built), 1)

    def test_handler_construction_failure_is_swallowed_not_silent(self):
        def boom(*a, **kw):
            raise OSError("permission denied")

        err = io.StringIO()
        with mock.patch.object(logging.handlers, "RotatingFileHandler",
                               boom):
            with redirect_stderr(err):
                result = hm.setup_logging()  # must not raise
        self.assertIsNone(result)
        self.assertEqual(self._rfh_count(), 0)
        self.assertIn("file logging unavailable", err.getvalue())


class _BundleBase(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()
        self._tmp = tempfile.TemporaryDirectory()
        self._cfg_patch = mock.patch.object(
            cfgm, "config_dir", return_value=Path(self._tmp.name))
        self._cfg_patch.start()

    def tearDown(self):
        self._cfg_patch.stop()
        self._tmp.cleanup()
        _restore_db(*self._db)


class BundleIsolationTests(_BundleBase):

    def test_happy_path_writes_all_sections(self):
        dest = hm.write_diagnostics_bundle(reason="test")
        self.assertIsNotNone(dest)
        for name in ("summary.txt", "config.redacted.yaml",
                     "db_check.txt", "threads.txt"):
            self.assertTrue((dest / name).exists(), name)
        self.assertIn("integrity_check: ok",
                      (dest / "db_check.txt").read_text())

    def test_summary_failure_does_not_abort_the_rest(self):
        real_write = Path.write_text

        def flaky(self, *a, **kw):
            if self.name == "summary.txt":
                raise OSError("disk full")
            return real_write(self, *a, **kw)

        with mock.patch.object(Path, "write_text", flaky):
            dest = hm.write_diagnostics_bundle(reason="test")
        self.assertIsNotNone(dest)
        # Pre-fix: the summary failure hit the outer handler and
        # sections 2-5 never ran.
        for name in ("config.redacted.yaml", "db_check.txt",
                     "threads.txt"):
            self.assertTrue((dest / name).exists(), name)

    def test_threads_failure_still_returns_bundle(self):
        real_write = Path.write_text

        def flaky(self, *a, **kw):
            if self.name == "threads.txt":
                raise OSError("disk full")
            return real_write(self, *a, **kw)

        with mock.patch.object(Path, "write_text", flaky):
            dest = hm.write_diagnostics_bundle(reason="test")
        self.assertIsNotNone(dest)
        self.assertTrue((dest / "summary.txt").exists())
        self.assertTrue((dest / "db_check.txt").exists())


class _TrackingConn(sqlite3.Connection):
    closed = False
    fail_integrity = False

    def execute(self, sql, *a, **kw):
        if self.fail_integrity and "integrity_check" in str(sql):
            raise sqlite3.OperationalError("simulated corruption")
        return super().execute(sql, *a, **kw)

    def close(self):
        type(self).closed = True
        super().close()


class BundleSqliteCloseTests(_BundleBase):

    def test_connection_closed_when_integrity_check_raises(self):
        _TrackingConn.closed = False
        _TrackingConn.fail_integrity = True
        real_connect = sqlite3.connect

        def tracking_connect(path, **kw):
            kw["factory"] = _TrackingConn
            return real_connect(path, **kw)

        with mock.patch.object(hm.sqlite3, "connect", tracking_connect):
            dest = hm.write_diagnostics_bundle(reason="test")
        self.assertIsNotNone(dest)
        # Pre-fix: close() sat after the raising call -- never reached.
        self.assertTrue(_TrackingConn.closed)
        self.assertIn("check failed",
                      (dest / "db_check.txt").read_text())

    def test_connection_closed_on_happy_path(self):
        _TrackingConn.closed = False
        _TrackingConn.fail_integrity = False
        real_connect = sqlite3.connect

        def tracking_connect(path, **kw):
            kw["factory"] = _TrackingConn
            return real_connect(path, **kw)

        with mock.patch.object(hm.sqlite3, "connect", tracking_connect):
            dest = hm.write_diagnostics_bundle(reason="test")
        self.assertIsNotNone(dest)
        self.assertTrue(_TrackingConn.closed)


if __name__ == "__main__":
    unittest.main()
