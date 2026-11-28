import sqlite3

db = sqlite3.connect(":memory:")
name = input("Table name: ")
query = f"SELECT name FROM sqlite_schema WHERE name = '{name}'"
db.execute(query)
