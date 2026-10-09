"""ok.py -- production run, no debug flag: zero findings for brutedash.flask.debug-true."""


def main():
    app.run(host="0.0.0.0", port=5000)
