import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/tables")
def lookup():
    name = request.args.get("name", "")
    db = sqlite3.connect(":memory:")
    db.execute("SELECT name FROM sqlite_schema WHERE name = ?", (name,))
    return "done"
