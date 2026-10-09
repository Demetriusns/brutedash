"""bad.py -- pickle on input: one finding for brutedash.python.pickle-load.

Fixture only: this code is never imported or executed.
"""
import pickle


def load_state(blob):
    return pickle.loads(blob)
