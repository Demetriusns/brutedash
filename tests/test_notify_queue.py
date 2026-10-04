"""Tests for the bounded notify queue: shed oldest, count drops, never block."""
import queue
import unittest

from netmon import notify as notifm


class NotifyQueueBoundTests(unittest.TestCase):
    def setUp(self):
        # Drain the shared queue and reset the drop counter so the test
        # is deterministic; the worker is never started here.
        while True:
            try:
                notifm._job_queue.get_nowait()
                notifm._job_queue.task_done()
            except queue.Empty:
                break
        with notifm._drop_lock:
            notifm._dropped_jobs = 0

    def tearDown(self):
        while True:
            try:
                notifm._job_queue.get_nowait()
                notifm._job_queue.task_done()
            except queue.Empty:
                break

    def test_queue_is_bounded(self):
        self.assertEqual(notifm._job_queue.maxsize, 100)

    def test_overflow_sheds_oldest_and_counts(self):
        for i in range(150):
            self.assertTrue(notifm._enqueue(("alert", {"n": i})))
        self.assertLessEqual(notifm._job_queue.qsize(), 100)
        self.assertEqual(notifm.dropped_job_count(), 50)
        # Freshest jobs survive: the last enqueued is at the tail.
        items = []
        while True:
            try:
                items.append(notifm._job_queue.get_nowait())
                notifm._job_queue.task_done()
            except queue.Empty:
                break
        self.assertEqual(items[-1][1]["n"], 149)

    def test_enqueue_never_blocks(self):
        import threading
        done = threading.Event()

        def flood():
            for i in range(500):
                notifm._enqueue(("alert", {"n": i}))
            done.set()

        t = threading.Thread(target=flood, daemon=True)
        t.start()
        self.assertTrue(done.wait(timeout=10), "enqueue blocked")
        t.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
