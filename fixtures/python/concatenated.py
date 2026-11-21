import sqlite3


def lookup():
    db = sqlite3.connect(":memory:")
    value = input("Item ID: ")
    query = "SELECT name FROM items WHERE id = " + value
    db.execute(query)
