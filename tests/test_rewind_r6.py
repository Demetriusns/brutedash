"""Rewind enforce_caps active-segment exemption — council review
2026-11-08, robustness R6. Shipped 2026-11-12 (daily build).

Pre-fix enforce_caps() iterated _segments() in both its time-cap and
size-cap loops with no exclusion of the segment currently open for
writing. Segment files are named by their open epoch and rotate only
every SEGMENT_SECONDS (300), while _caps() permits rewind_minutes as
low as 1.0 and the monitor loop sweeps enforce_caps() every 60s — so
an open segment's name legitimately ages past a small configured
cutoff while packets are still being appended to it. On POSIX the
unlink succeeded: record_packet() kept writing to an unlinked inode,
status() under-reported the buffer, and exports silently missed
everything since the unlink. On Windows the unlink raised OSError
and was retried every sweep.

Post-fix: _rotate() tracks the active segment's path in _seg_path,
and enforce_caps() skips the active segment in both loops — the time
cap keeps it outright; the size cap keeps it, removes its size from
the eviction total (the L6 undeletable-segment treatment, so the
protection cannot drive deletion of newer segments), and logs one
stderr line when the active segment alone exceeds the cap. The
segment becomes evictable at the next rotation. Identification is
path equality (realpath) with a start-epoch fallback for state
constructed without _rotate().

Run: python -m unittest discover -s tests -v
"""
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import rewind as rwm


class _R6Case(unittest.TestCase):
    def setUp(self):
        rwm._reset_for_tests()
        self.tmp = tempfile.mkdtemp(prefix="rewind-r6-")
        self.now = time.time()
        self._old_dir = rwm.rewind_dir
        self._old_caps = rwm._caps
        rwm.rewind_dir = lambda: Path(self.tmp)

    def tearDown(self):
        rwm._reset_for_tests()
        rwm.rewind_dir = self._old_dir
        rwm._caps = self._old_caps
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seg(self, start, size):
        p = Path(self.tmp) / f"seg_{int(start):010d}.pcap"
        p.write_bytes(b"x" * size)
        return p

    def _make_active(self, start, size, with_path=True):
        """A segment file plus the module state of it being written."""
        p = self._seg(start, size)
        fh = open(p, "ab")
        rwm._seg_file = fh
        rwm._seg_start = int(start)
        rwm._seg_bytes = size
        rwm._seg_path = p if with_path else None
        return p

    def _set_caps(self, minutes, max_bytes):
        rwm._caps = lambda: (float(minutes), float(max_bytes))

    def _remaining(self):
        return sorted(p.name for p in Path(self.tmp).glob("seg_*.pcap"))


class EnforceCapsR6Tests(_R6Case):
    def test_active_segment_survives_time_cap(self):
        # Active aged 120s with a 1-minute retention: pre-fix it was
        # unlinked while its handle was still open (kept=0); the
        # older CLOSED segment must still be evicted.
        active = self._make_active(self.now - 120, 100)
        old = self._seg(self.now - 7200, 100)
        self._set_caps(1, 10 ** 9)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 100))
        self.assertEqual(self._remaining(), [active.name])
        self.assertFalse(old.exists())

    def test_active_identified_by_start_when_path_untracked(self):
        # The head repro shape: state built by hand (_seg_path None)
        # is still protected via the start-epoch fallback.
        active = self._make_active(self.now - 120, 100, with_path=False)
        self._set_caps(1, 10 ** 9)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 0))
        self.assertEqual(self._remaining(), [active.name])

    def test_active_segment_alone_over_size_cap_is_kept(self):
        active = self._make_active(self.now - 10, 300)
        self._set_caps(60, 150)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 0))
        self.assertEqual(self._remaining(), [active.name])

    def test_active_does_not_drive_eviction_of_newest(self):
        # old closed 100 + active 100 + newest closed 100, cap 150:
        # evict the old one, skip the active (its size leaves the
        # eviction total), and the newest survives. Pre-fix the
        # active segment was evicted as the second deletion.
        old = self._seg(self.now - 100, 100)
        active = self._make_active(self.now - 99, 100)
        newest = self._seg(self.now - 98, 100)
        self._set_caps(60, 150)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (2, 100))
        self.assertEqual(self._remaining(), [active.name, newest.name])
        self.assertFalse(old.exists())

    def test_closed_segments_evict_as_before(self):
        # Guard: with nothing active, size eviction is unchanged.
        p0 = self._seg(self.now - 100, 100)
        self._seg(self.now - 99, 100)
        p2 = self._seg(self.now - 98, 100)
        self._set_caps(60, 150)
        kept, freed = rwm.enforce_caps(now=self.now)
        self.assertEqual((kept, freed), (1, 200))
        self.assertEqual(self._remaining(), [p2.name])
        self.assertFalse(p0.exists())

    def test_segment_evictable_after_rotation(self):
        # Once _rotate() closes a segment it is evictable again: with
        # a far-future sweep, the rotated-away segment goes and only
        # the NEW active segment is protected.
        old_active = self._make_active(self.now - 120, 100)
        with rwm._lock:
            rwm._rotate(self.now)
        new_active = rwm._seg_path
        self.assertIsNotNone(new_active)
        self._set_caps(1, 10 ** 9)
        kept, freed = rwm.enforce_caps(now=self.now + 3600)
        self.assertEqual(kept, 1)
        self.assertEqual(self._remaining(), [new_active.name])
        self.assertFalse(old_active.exists())


if __name__ == "__main__":
    unittest.main()
