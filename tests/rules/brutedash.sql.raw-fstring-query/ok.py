"""ok.py -- parameterized queries: zero findings for brutedash.sql.raw-fstring-query."""


def lookup_user(cursor, username):
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()


def count_devices(db):
    db.execute("SELECT COUNT(*) FROM devices", ())
    return db.fetchone()[0]
