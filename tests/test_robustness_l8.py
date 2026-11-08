"""Tests for the 2026-11-08 daily build: robustness L8 (council
review 2026-11-01, finding 8) -- ipintel failure handling.

L8a: lookup_ip() closes its SQLite connection on EVERY path. Pre-fix,
conn.close() ran only on the cache-hit and success paths; the bare
``except Exception: return {}`` path leaked the handle whenever
_fetch() raised.
L8b: failed lookups are negative-cached for NEGATIVE_CACHE_TTL
(10 minutes). Pre-fix, failures were never cached, so during an
ip-api outage every /brief request re-ran urlopen(timeout=5) for the
same IP -- one 5s stall per click, per IP, for the whole outage.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import ipintel
except ImportError:
    ipintel = None

POSITIVE = {"country": "Netherlands", "org": "Example ISP",
            "proxy": False, "hosting": True}


class _TrackingConn:
    """Wrap a real sqlite connection and record close() calls."""

    def __init__(self, inner):
        self._inner = inner
        self.closed = False

    def execute(self, *args, **kwargs):
        return self._inner.execute(*args, **kwargs)

    def commit(self):
        return self._inner.commit()

    def close(self):
        self.closed = True
        return self._inner.close()


@unittest.skipIf(ipintel is None, "ipintel unavailable")
class TestIpintelL8(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._old_db_path = ipintel.DB_PATH
        self._old_fetch = ipintel._fetch
        self._old_db = ipintel._db
        ipintel.DB_PATH = os.path.join(self._tmp.name, "detections.db")
        self.addCleanup(self._restore)

    def _restore(self):
        ipintel.DB_PATH = self._old_db_path
        ipintel._fetch = self._old_fetch
        ipintel._db = self._old_db

    def _counting_fetch(self, behaviour):
        calls = []

        def _fetch(ip):
            calls.append(ip)
            if isinstance(behaviour, Exception):
                raise behaviour
            return behaviour

        ipintel._fetch = _fetch
        return calls

    def _track_db(self):
        real_db = self._old_db
        holder = {}

        def _db():
            conn = _TrackingConn(real_db())
            holder["conn"] = conn
            return conn

        ipintel._db = _db
        return holder

    def _stored_row(self, ip):
        conn = self._old_db()
        try:
            return conn.execute(
                "SELECT country, org, proxy, hosting, fetched_at "
                "FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
        finally:
            conn.close()

    def _backdate(self, ip, seconds):
        conn = self._old_db()
        try:
            conn.execute(
                "UPDATE ip_intel SET fetched_at = ? WHERE ip = ?",
                (time.time() - seconds, ip))
            conn.commit()
        finally:
            conn.close()

    # -- L8a: connection closed on every path -----------------------

    def test_fetch_exception_still_closes_connection(self):
        holder = self._track_db()
        self._counting_fetch(RuntimeError("network down"))
        self.assertEqual(ipintel.lookup_ip("203.0.113.10"), {})
        self.assertTrue(holder["conn"].closed)

    def test_fetch_success_closes_connection(self):
        holder = self._track_db()
        self._counting_fetch(dict(POSITIVE))
        self.assertEqual(ipintel.lookup_ip("203.0.113.11"), POSITIVE)
        self.assertTrue(holder["conn"].closed)

    def test_empty_fetch_closes_connection(self):
        holder = self._track_db()
        self._counting_fetch({})
        self.assertEqual(ipintel.lookup_ip("203.0.113.12"), {})
        self.assertTrue(holder["conn"].closed)

    # -- L8b: negative cache ----------------------------------------

    def test_empty_fetch_negative_cached(self):
        calls = self._counting_fetch({})
        self.assertEqual(ipintel.lookup_ip("203.0.113.13"), {})
        self.assertEqual(ipintel.lookup_ip("203.0.113.13"), {})
        self.assertEqual(len(calls), 1)

    def test_exception_fetch_negative_cached(self):
        calls = self._counting_fetch(RuntimeError("network down"))
        self.assertEqual(ipintel.lookup_ip("203.0.113.14"), {})
        self.assertEqual(ipintel.lookup_ip("203.0.113.14"), {})
        self.assertEqual(len(calls), 1)

    def test_negative_row_is_marker_not_positive_result(self):
        self._counting_fetch({})
        ipintel.lookup_ip("203.0.113.15")
        row = self._stored_row("203.0.113.15")
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "")
        self.assertEqual(row[1], "")
        # And a fresh negative row reads back as {}, never as a
        # dict with empty country/org.
        self.assertEqual(ipintel.lookup_ip("203.0.113.15"), {})

    def test_negative_cache_expires_and_recovers(self):
        calls = self._counting_fetch({})
        self.assertEqual(ipintel.lookup_ip("203.0.113.16"), {})
        self.assertEqual(len(calls), 1)
        self._backdate("203.0.113.16", ipintel.NEGATIVE_CACHE_TTL + 60)
        calls2 = self._counting_fetch(dict(POSITIVE))
        self.assertEqual(ipintel.lookup_ip("203.0.113.16"), POSITIVE)
        self.assertEqual(len(calls2), 1)
        # The recovered positive result replaces the negative row
        # and is served from the normal 24h cache afterwards.
        self.assertEqual(ipintel.lookup_ip("203.0.113.16"), POSITIVE)
        self.assertEqual(len(calls2), 1)

    # -- behaviour guard: positive caching unchanged -----------------

    def test_positive_result_cached_for_24h(self):
        calls = self._counting_fetch(dict(POSITIVE))
        self.assertEqual(ipintel.lookup_ip("203.0.113.17"), POSITIVE)
        self.assertEqual(ipintel.lookup_ip("203.0.113.17"), POSITIVE)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
