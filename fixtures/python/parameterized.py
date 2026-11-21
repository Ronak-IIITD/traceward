import sqlite3


def lookup():
    db = sqlite3.connect(":memory:")
    value = input("Item ID: ")
    db.execute("SELECT name FROM items WHERE id = ?", (value,))
