"""bad.py -- debug flag shipped: one finding for brutedash.flask.debug-true.

Fixture only: this code is never imported or executed.

Note: the rule shape requires an argument after the debug flag, so the
fixture places it mid-arguments.
"""


def main():
    app.run(host="0.0.0.0", debug=True, port=5000)
