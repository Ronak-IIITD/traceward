import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.get("/tables")
def lookup():
    name = request.args.get("name", "")
    db = sqlite3.connect(":memory:")
    query = "SELECT name FROM sqlite_schema WHERE name = '" + name + "'"
    db.execute(query)
    return "done"
