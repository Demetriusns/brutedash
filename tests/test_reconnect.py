"""Tests for _ReconnectingConnection: dead-handle recovery, no more."""
import sqlite3
import tempfile
import os
import unittest

from netmon import db as dbm


class ReconnectTests(unittest.TestCase):
    def _proxy_on_tmp(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        path = tmp.name
        proxy = dbm._connect(path)
        proxy.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
        proxy.commit()
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return proxy

    def test_normal_ops_delegate(self):
        proxy = self._proxy_on_tmp()
        proxy.execute("INSERT INTO t(v) VALUES ('x')")
        proxy.commit()
        row = proxy.execute("SELECT v FROM t").fetchone()
        self.assertEqual(row[0], "x")
        proxy.close()

    def test_closed_handle_reconnects_once(self):
        proxy = self._proxy_on_tmp()
        proxy.execute("INSERT INTO t(v) VALUES ('a')")
        proxy.commit()
        # Kill the underlying connection out from under the proxy.
        proxy._conn.close()
        # Next op hits ProgrammingError("closed") -> one reconnect -> works.
        row = proxy.execute("SELECT COUNT(*) FROM t").fetchone()
        self.assertEqual(row[0], 1)
        proxy.close()

    def test_non_dead_errors_propagate_without_reconnect(self):
        proxy = self._proxy_on_tmp()
        first_conn = proxy._conn
        with self.assertRaises(sqlite3.OperationalError):
            proxy.execute("SELECT * FROM no_such_table_xyz")
        # Same underlying connection: no reconnect was attempted.
        self.assertIs(proxy._conn, first_conn)
        proxy.close()

    def test_lock_errors_are_not_dead(self):
        proxy = self._proxy_on_tmp()
        # The classifier is the decision point: a lock error must never
        # be treated as a dead connection (retry storms live here).
        self.assertFalse(proxy._is_dead_error(
            sqlite3.OperationalError("database is locked")))
        self.assertFalse(proxy._is_dead_error(
            sqlite3.OperationalError("database is busy")))
        self.assertTrue(proxy._is_dead_error(
            sqlite3.ProgrammingError("Cannot operate on a closed database.")))
        proxy.close()

    def test_close_stays_closed(self):
        proxy = self._proxy_on_tmp()
        proxy.close()
        with self.assertRaises(Exception):
            proxy.execute("SELECT 1")
        # Still the same (closed) connection: close() disables reconnect.
        self.assertTrue(proxy._closed)


if __name__ == "__main__":
    unittest.main()
