"""Rewind enforce_caps failure isolation — council review 2026-11-01,
robustness L6. Shipped 2026-11-05 (daily build).

Pre-fix enforce_caps() had two failure-amplification bugs:
(a) the size total was one sum() in a single try — one segment
    vanishing mid-pass (stat OSError) zeroed the total and disabled
    the size cap for the whole pass;
(b) the eviction loop popped the oldest segment before trying to
    unlink it and never decremented the total on failure — one
    locked/undeletable segment kept total > max_bytes true and the
    loop deleted EVERY remaining segment chasing an unreachable
    target. The time-cap loop also counted a segment's bytes as
    freed before its unlink ran, over-reporting freed on failure.

Post-fix: per-file stat (a stat failure is treated as vanished and
only that file is skipped), eviction uses the measured sizes, only
a successful unlink decrements the total, and an undeletable
segment stays on disk, counts in kept, and its size leaves the
eviction total so it cannot drive further deletions this pass.

Run: python -m unittest discover -s tests -v
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import rewind as rwm


class _CapsCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rewind-caps-")
        self.now = time.time()
        self._old_dir = rwm.rewind_dir
        self._old_caps = rwm._caps
        rwm.rewind_dir = lambda: Path(self.tmp)

    def tearDown(self):
        rwm.rewind_dir = self._old_dir
        rwm._caps = self._old_caps
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seg(self, offset_s, size):
        start = int(self.now) - 100 + offset_s
        p = Path(self.tmp) / f"seg_{start}.pcap"
        p.write_bytes(b"x" * size)
        return start, p

    def _set_caps(self, minutes, max_bytes):
        rwm._caps = lambda: (float(minutes), float(max_bytes))

    def _remaining(self):
        return sorted(p.name for p in Path(self.tmp).glob("seg_*.pcap"))


class EnforceCapsL6Tests(_CapsCase):
    def test_locked_oldest_evicts_only_enough_deletable(self):
        # 3x100B, cap 150B, oldest unlink locked: post-fix only the
        # middle segment is deleted (freed 100, total 100 <= 150 once
        # the locked 100 leaves the eviction total); pre-fix deleted
        # both deletable segments and returned kept=0.
        _s0, p0 = self._seg(0, 100)
        _s1, p1 = self._seg(1, 100)
        _s2, p2 = self._seg(2, 100)
        self._set_caps(60, 150)
        real_unlink = Path.unlink

        def flaky(self, *a, **k):
            if self == p0:
                raise OSError("locked")
            return real_unlink(self, *a, **k)

        with mock.patch.object(Path, "unlink", flaky):
            kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (2, 100))
        self.assertEqual(self._remaining(), [p0.name, p2.name])

    def test_vanished_segment_does_not_disable_size_cap(self):
        # A segment present in the listing but gone by stat time:
        # the cap must still enforce on the two real files (200B
        # over a 150B cap deletes the oldest); pre-fix total was
        # zeroed and nothing was deleted.
        s0, p0 = self._seg(0, 100)
        s2, p2 = self._seg(2, 100)
        ghost = Path(self.tmp) / f"seg_{int(self.now) - 99}.pcap"
        self._set_caps(60, 150)
        with mock.patch.object(
            rwm, "_segments",
            return_value=[(s0, p0), (int(self.now) - 99, ghost),
                          (s2, p2)],
        ):
            kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 100))
        self.assertEqual(self._remaining(), [p2.name])

    def test_time_cap_failed_unlink_keeps_segment_and_freed(self):
        # Old segment (outside the 60-minute window) whose unlink
        # fails: it is kept and its bytes are NOT counted as freed;
        # pre-fix counted them as freed before the unlink ran.
        start = int(self.now) - 7200
        p = Path(self.tmp) / f"seg_{start}.pcap"
        p.write_bytes(b"x" * 100)
        self._set_caps(60, 10 ** 9)
        with mock.patch.object(Path, "unlink",
                               side_effect=OSError("locked")):
            kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 0))
        self.assertEqual(self._remaining(), [p.name])

    def test_all_unlinks_fail_never_raises_and_keeps_all(self):
        self._seg(0, 100)
        self._seg(1, 100)
        self._seg(2, 100)
        self._set_caps(60, 150)
        with mock.patch.object(Path, "unlink",
                               side_effect=OSError("locked")):
            kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (3, 0))
        self.assertEqual(len(self._remaining()), 3)

    def test_normal_size_eviction_unchanged(self):
        _s0, p0 = self._seg(0, 100)
        _s1, p1 = self._seg(1, 100)
        _s2, p2 = self._seg(2, 100)
        self._set_caps(60, 150)
        kept, freed = rwm.enforce_caps(now=self.now)
        # 300B over a 150B cap: evict oldest two, newest kept.
        self.assertEqual((kept, freed), (1, 200))
        self.assertEqual(self._remaining(), [p2.name])

    def test_normal_time_eviction_unchanged(self):
        start = int(self.now) - 7200
        old = Path(self.tmp) / f"seg_{start}.pcap"
        old.write_bytes(b"x" * 100)
        _s, new = self._seg(0, 100)
        self._set_caps(60, 10 ** 9)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 100))
        self.assertEqual(self._remaining(), [new.name])


if __name__ == "__main__":
    unittest.main()
