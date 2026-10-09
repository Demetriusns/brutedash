"""ok.py -- json, not pickle: zero findings for brutedash.python.pickle-load."""
import json


def load_state(blob):
    return json.loads(blob)
