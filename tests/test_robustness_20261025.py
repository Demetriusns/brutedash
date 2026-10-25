"""Tests for robustness R8 (2026-10-18 council review, shipped
2026-10-25).

R8 -- pipeline.safe_step bounded exceptions, not hangs: it was a
synchronous try/except wrapper, and _monitor_loop runs every step
sequentially on one thread, so one long step (nuclei's subprocess
timeout can exceed 4 hours) wedged the whole loop -- no detection
pass, no capture watchdog, no staleness check until it returned.

Fix: safe_step gains an optional `timeout` keyword. With it, fn runs
on a daemon worker thread and the caller waits at most that long;
an overrun logs one line and returns None while the worker finishes
in the background (the deadline detaches, it does not kill). A
registry of in-flight timed steps prevents a duplicate spawn on the
next pass. Without `timeout`, behaviour is unchanged. run.py wires
the deadline (one DETECT_INTERVAL) to weekly-scan, amass and nuclei
only.

Run: python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import pipeline as pipelinem


class TestTimedSafeStep(unittest.TestCase):
    def tearDown(self):
        # A leaked registry entry would poison later tests.
        deadline = time.time() + 5
        while pipelinem._timed_inflight and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(pipelinem._timed_inflight, {})

    def test_timed_step_finishing_in_time_returns_value(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = pipelinem.safe_step("quick", lambda: 42, timeout=5)
        self.assertEqual(out, 42)
        self.assertEqual(err.getvalue(), "")

    def test_timed_step_passes_args_and_kwargs(self):
        def _add(a, b=0):
            return a + b

        out = pipelinem.safe_step("adder", _add, 2, b=3, timeout=5)
        self.assertEqual(out, 5)

    def test_timed_step_raising_in_time_logs_and_returns_none(self):
        def _boom():
            raise RuntimeError("timed poison")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = pipelinem.safe_step("badstep", _boom, timeout=5)
        self.assertIsNone(out)
        self.assertIn("step badstep failed", err.getvalue())
        self.assertIn("timed poison", err.getvalue())

    def test_overrun_returns_promptly_and_worker_completes(self):
        finished = threading.Event()

        def _slow():
            time.sleep(0.4)
            finished.set()
            return "late"

        start = time.monotonic()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = pipelinem.safe_step("slowstep", _slow, timeout=0.05)
        elapsed = time.monotonic() - start
        self.assertIsNone(out)
        self.assertLess(elapsed, 0.35)  # did NOT wait for the step
        self.assertIn("step slowstep overran", err.getvalue())
        # The worker is not killed: it finishes and clears the registry.
        self.assertTrue(finished.wait(2))
        deadline = time.time() + 2
        while pipelinem._timed_inflight and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(pipelinem._timed_inflight, {})

    def test_second_call_same_name_skipped_while_in_flight(self):
        release = threading.Event()
        calls = []

        def _blocked():
            calls.append(1)
            release.wait(5)
            return 1

        with contextlib.redirect_stderr(io.StringIO()) as err:
            first = pipelinem.safe_step("dupstep", _blocked, timeout=0.05)
            second = pipelinem.safe_step("dupstep", _blocked, timeout=0.05)
            release.set()
        self.assertIsNone(first)   # overran its deadline
        self.assertIsNone(second)  # skipped, not spawned again
        self.assertIn("still running from an earlier pass",
                      err.getvalue())
        deadline = time.time() + 2
        while pipelinem._timed_inflight and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(calls), 1)  # fn ran exactly once

    def test_detached_worker_late_failure_is_logged_once(self):
        release = threading.Event()

        def _late_boom():
            release.wait(5)
            raise RuntimeError("late poison")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = pipelinem.safe_step("latestep", _late_boom,
                                      timeout=0.05)
            self.assertIsNone(out)
            release.set()
            deadline = time.time() + 2
            while "late poison" not in err.getvalue() \
                    and time.time() < deadline:
                time.sleep(0.01)
        text = err.getvalue()
        self.assertIn("step latestep overran", text)
        self.assertEqual(text.count("step latestep failed"), 1)
        self.assertIn("late poison", text)

    def test_sync_default_path_unchanged(self):
        def _boom():
            raise RuntimeError("sync poison")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(pipelinem.safe_step("syncstep", _boom))
        self.assertIn("step syncstep failed", err.getvalue())
        self.assertEqual(pipelinem.safe_step("syncok", lambda: 7), 7)
        self.assertEqual(pipelinem._timed_inflight, {})


class TestRunWiring(unittest.TestCase):
    def test_deadline_wired_to_exactly_the_three_long_steps(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "netmon", "run.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        for step in ("weekly-scan", "amass", "nuclei"):
            self.assertIn(f'safe_step("{step}"', src)
        # The three calls are the only timeout=DETECT_INTERVAL uses.
        self.assertEqual(src.count("timeout=DETECT_INTERVAL"), 3)


if __name__ == "__main__":
    unittest.main()
