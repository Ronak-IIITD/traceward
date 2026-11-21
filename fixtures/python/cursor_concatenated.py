import sqlite3


def lookup():
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    name = input()
    cursor.execute("SELECT name FROM items WHERE name = '" + name + "'")
