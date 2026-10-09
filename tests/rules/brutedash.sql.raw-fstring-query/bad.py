"""bad.py -- raw f-string SQL: two findings for brutedash.sql.raw-fstring-query.

Fixture only: this code is never imported or executed.
"""


def lookup_user(cursor, username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'", ())


def count_devices(db):
    db.execute(f"SELECT COUNT(*) FROM {devices_table}", ())
