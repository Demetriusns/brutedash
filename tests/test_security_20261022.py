"""Tests for the 2026-10-22 batch: security L3/L4/L5 (2026-10-18 review).

L3: render.yaml ran the public demo with 2 gunicorn workers while
app.py's rate limiters are per-process dicts -- every cap was silently
doubled. The demo now runs 1 worker x 4 threads.

L4: /api/ask had no question-length cap (only the 100MB body limit)
before the question was interpolated verbatim into the LLM prompt.
The route now rejects >2000 chars with 400, and
ai_assist.answer_question truncates defensively at the same bound.

L5: parse_security_xml fed watch-dir XML straight to stdlib
ElementTree, which has no entity-expansion (billion-laughs)
protection. Files declaring <!ENTITY are now rejected unparsed with
the same ([], 1) shape as a parse error; Event Viewer exports never
declare entities.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, scratch_file
from netmon import ai_assist as assistm
from netmon import ingest as ingm

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")

_XML_SAMPLE = """\
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-03T14:22:01.1234567Z"/><Computer>PC-01</Computer><Channel>Security</Channel></System>
<EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="LogonType">3</Data></EventData>
</Event>
</Events>
"""

_XML_LOL = """\
<?xml version="1.0"?>
<!DOCTYPE Events [
<!ENTITY a "xxxxxxxxxx">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-03T14:22:01Z"/><Computer>PC-01</Computer><Channel>Security</Channel></System>
<EventData><Data Name="TargetUserName">&c;</Data><Data Name="IpAddress">203.0.113.9</Data></EventData>
</Event>
</Events>
"""


class TestRenderYamlWorkers(unittest.TestCase):
    def test_single_worker_with_threads(self):
        with open(os.path.join(_REPO_ROOT, "render.yaml"),
                  encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("--workers 1", text)
        self.assertIn("--threads 4", text)
        self.assertNotIn("--workers 2", text)


class _RecordingAssist:
    """Stub ai_assist: LLM on, records every question it is handed."""

    def __init__(self):
        self.questions = []

    def llm_available(self):
        return True

    def answer_question(self, question):
        self.questions.append(question)
        return "stub answer"


@unittest.skipIf(dashm is None, "Flask not installed")
class TestAskLengthCap(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        dashm._AI_ASK_USAGE.clear()
        self._real_assist = dashm._ai_assist
        self._real_limits = dashm._ai_ask_limits
        dashm._ai_ask_limits = lambda: (100, 1000)  # keep limiter out
        self.stub = _RecordingAssist()
        dashm._ai_assist = lambda: self.stub

    def tearDown(self):
        dashm._ai_assist = self._real_assist
        dashm._ai_ask_limits = self._real_limits
        dashm._AI_ASK_USAGE.clear()
        super().tearDown()

    def _ask(self, c, q):
        return c.post("/api/ask", json={"question": q},
                      environ_base={"REMOTE_ADDR": "10.7.7.7"})

    def test_overlong_question_400_and_never_reaches_llm(self):
        c = dashm.app.test_client()
        r = self._ask(c, "x" * 2001)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["error"], "question too long")
        self.assertEqual(self.stub.questions, [])

    def test_exactly_2000_chars_accepted(self):
        c = dashm.app.test_client()
        r = self._ask(c, "x" * 2000)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.stub.questions, ["x" * 2000])

    def test_normal_question_accepted(self):
        c = dashm.app.test_client()
        r = self._ask(c, "anything up?")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.stub.questions, ["anything up?"])


class TestAnswerQuestionTruncation(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_client = assistm._client
        self._old_json_chat = assistm._json_chat
        assistm._client = lambda: object()  # fake: model "available"
        self.prompts = []

        def _fake_chat(client, prompt, max_tokens=400):
            self.prompts.append(prompt)
            return {"answer": "ok"}

        assistm._json_chat = _fake_chat

    def tearDown(self):
        assistm._client = self._old_client
        assistm._json_chat = self._old_json_chat
        super().tearDown()

    def test_overlong_question_truncated_before_prompt(self):
        ans = assistm.answer_question("q" * 2500)
        self.assertEqual(ans, {"answer": "ok"})
        self.assertEqual(len(self.prompts), 1)
        self.assertIn("q" * 2000, self.prompts[0])
        self.assertNotIn("q" * 2001, self.prompts[0])


class TestIngestEntityGuard(unittest.TestCase):
    def _parse(self, text):
        with scratch_file(suffix=".xml", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return ingm.parse_security_xml(path)

    def test_entity_declaring_file_rejected(self):
        events, skipped = self._parse(_XML_LOL)
        self.assertEqual(events, [])
        self.assertEqual(skipped, 1)

    def test_lowercase_entity_marker_rejected(self):
        events, skipped = self._parse(
            _XML_LOL.replace("<!ENTITY", "<!entity"))
        self.assertEqual(events, [])
        self.assertEqual(skipped, 1)

    def test_marker_split_across_scan_chunks_rejected(self):
        # Pad so the marker straddles the _SCAN_CHUNK boundary: the
        # scanner's carried tail must still catch it.
        pad = ingm._SCAN_CHUNK - 4
        text = "A" * pad + '<!ENTITY a "x">'
        with scratch_file(suffix=".xml", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.assertTrue(ingm._declares_entities(path))

    def test_normal_export_still_parses(self):
        events, skipped = self._parse(_XML_SAMPLE)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][2], "4625")

    def test_doctype_without_entity_still_parses(self):
        events, skipped = self._parse(
            '<?xml version="1.0"?>\n<!DOCTYPE Events>\n' + _XML_SAMPLE)
        self.assertEqual(skipped, 0)
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
