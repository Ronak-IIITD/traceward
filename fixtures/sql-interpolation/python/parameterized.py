import sqlite3

db = sqlite3.connect(":memory:")
name = input("Table name: ")
bound = f"{name}"
db.execute("SELECT name FROM sqlite_schema WHERE name = ?", (bound,))
