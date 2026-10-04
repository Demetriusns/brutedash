"""Shared test helpers for the brutedash unittest suite (stdlib only).

The recurring /tmp leak: every test that pointed the DB at a
``tempfile.NamedTemporaryFile(suffix=".db")`` cleaned up only the ``.db``
file itself. SQLite in WAL mode leaves ``.db-wal`` and ``.db-shm``
sidecars behind, and a few hundred test runs filled /tmp twice.

Use these helpers in every test file so temp DBs (and their sidecars)
are always removed in tearDown:

    from helpers import ScratchDbTestCase        # base class, or
    from helpers import fresh_db, restore_db    # manual setUp/tearDown
    from helpers import scratch_db              # context manager
    from helpers import scratch_file, scratch_dir  # temp files / dirs

``unittest discover -s tests`` puts ``tests/`` on sys.path, so
``import helpers`` works from any test module.
"""
import contextlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm

# SQLite sidecar suffixes. -wal/-shm come from WAL mode; -journal from
# rollback-journal mode. Removing the main file is not enough.
_SIDECARS = ("-wal", "-shm", "-journal")


def _remove_tree(path):
    """Remove a file plus every SQLite sidecar, ignoring missing files."""
    for suffix in ("",) + _SIDECARS:
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def fresh_db():
    """Point the DB layer at a fresh temp DB.

    Returns (path, old_path, old_conn) for restore_db(). Mirrors the
    helper every test file used to copy-paste locally.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    old_path, old_conn = dbm.DB_PATH, dbm._conn
    dbm.DB_PATH = tmp.name
    dbm._conn = None
    return tmp.name, old_path, old_conn


def restore_db(path, old_path, old_conn):
    """Restore the previous DB and delete the temp DB + all sidecars."""
    try:
        if dbm._conn is not None:
            try:
                dbm._conn.close()
            except Exception:
                pass
    finally:
        dbm.DB_PATH, dbm._conn = old_path, old_conn
    _remove_tree(path)


@contextlib.contextmanager
def scratch_db():
    """Context manager version of fresh_db()/restore_db()."""
    state = fresh_db()
    try:
        yield state[0]
    finally:
        restore_db(*state)


class ScratchDbTestCase(unittest.TestCase):
    """Base class: each test runs against a fresh temp DB that is fully
    removed (db + -wal + -shm) in tearDown."""

    def setUp(self):
        self._db_state = fresh_db()

    def tearDown(self):
        restore_db(*self._db_state)


@contextlib.contextmanager
def scratch_file(suffix="", prefix="test-", mode="w+b"):
    """A temp file that is always deleted on exit (unlike
    NamedTemporaryFile(delete=False), which leaks when the test forgets)."""
    tmp = tempfile.NamedTemporaryFile(
        suffix=suffix, prefix=prefix, delete=False, mode=mode)
    tmp.close()
    try:
        yield tmp.name
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


@contextlib.contextmanager
def scratch_dir(prefix="test-"):
    """A temp directory that is always removed on exit (unlike a bare
    tempfile.mkdtemp(), which leaks)."""
    with tempfile.TemporaryDirectory(prefix=prefix) as d:
        yield d
