"""Tiny Flask app used only as a ThreatSketch test fixture. Not for production."""
import os
import sqlite3

from flask import Flask, jsonify, request, session

from auth import check_password

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev")
DB_PATH = os.getenv("DATABASE_PATH", "notes.db")


def db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    if check_password(data.get("username", ""), data.get("password", "")):
        session["user"] = data["username"]
        return jsonify(ok=True)
    return jsonify(ok=False), 401


@app.route("/notes")
def list_notes():
    rows = db().execute("SELECT id, body FROM notes WHERE owner = ?", (session.get("user"),)).fetchall()
    return jsonify(rows)


@app.route("/notes", methods=["POST"])
def add_note():
    body = (request.get_json() or {}).get("body", "")
    conn = db()
    conn.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (session.get("user"), body))
    conn.commit()
    return jsonify(ok=True), 201


@app.route("/admin/export")
def export():
    return jsonify(db().execute("SELECT * FROM notes").fetchall())


if __name__ == "__main__":
    app.run(debug=True)
