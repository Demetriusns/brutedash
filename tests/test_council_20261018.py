"""Regression tests for the 2026-10-18 council batch (non-weekly parts).

- app.py write_brief built the OpenAI client with no timeout -- the
  one call site the 2026-10-04 timeout fix missed (security M1 +
  robustness R4, two-seat quorum). ai_assist.py and explainer.py both
  use timeout=30; app.py must match.
- "A quiet network is a healthy network" survived in three
  user-facing spots (reporting score explanation, morning briefing,
  attack-surface summary) after the 2026-10-11 cycle removed the
  doctor metaphor from the dashboard (UX finding 1, standing voice
  rule: medical metaphor is internal-only).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import attacksurface as asm
from netmon import reporting as repm

ROOT = os.path.join(os.path.dirname(__file__), "..")


class AppTimeoutTest(unittest.TestCase):
    def test_app_openai_client_has_timeout(self):
        with open(os.path.join(ROOT, "app.py")) as f:
            src = f.read()
        self.assertIn("OpenAI(api_key=api_key, timeout=30)", src)


class HealthyCopyTest(unittest.TestCase):
    def test_score_explanation_has_no_doctor_metaphor(self):
        text = repm.explain_score({"score": 100, "factors": []})
        self.assertNotIn("healthy", text)
        self.assertIn("good sign", text)

    def test_attack_surface_summary_has_no_doctor_metaphor(self):
        text = asm._summary_line({}, [])
        self.assertNotIn("healthy", text)
        self.assertIn("good sign", text)

    def test_no_healthy_network_in_user_facing_modules(self):
        for rel in ("netmon/reporting.py", "netmon/attacksurface.py"):
            with open(os.path.join(ROOT, rel)) as f:
                self.assertNotIn("healthy network", f.read(), rel)


if __name__ == "__main__":
    unittest.main()
