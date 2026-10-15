#!/usr/bin/env python3
"""
Mosaic Credential — Live Authentication & Database Testing Server
Full-stack testing server using Flask, SQLite, and the Mosaic Credential library.
"""

import json
import os
import sqlite3
import sys
import base64
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

# Add mosaic-python to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "mosaic-python"))

from mosaic_credential import (
    AuthParams,
    Blob,
    Char,
    CredentialBuilder,
    Policy,
    ResourceLimits,
    VerifierRecord,
    VerifyResult,
    enroll,
    verify,
    parse,
)

app = Flask(__name__, static_folder="static", static_url_path="")
DB_PATH = Path(__file__).resolve().parent / "auth.db"


def get_db():
    """Connect to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize the SQLite users table (§9)."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                credential_record TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def parse_elements_from_json(elements_data):
    """Convert JSON element list to Mosaic Element objects."""
    elements = []
    for item in elements_data:
        el_type = item.get("type", "").upper()
        if el_type == "CHAR":
            ch = item.get("char", "")
            if not ch:
                cp = item.get("codepoint", 0)
                ch = chr(cp)
            elements.append(Char(ch))
        elif el_type == "BLOB":
            hex_data = item.get("hex", "")
            raw_bytes = bytes.fromhex(hex_data)
            elements.append(Blob(raw_bytes))
        else:
            raise ValueError(f"Unknown element type: {el_type}")
    return elements


@app.route("/")
def index():
    """Serve the web app entry point."""
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/register", methods=["POST"])
def api_register():
    """
    Enroll a new user (§10.1).
    Receives: { username: str, elements: list, fast_mode: bool }
    Stores: VerifierRecord into SQLite.
    """
    try:
        data = request.get_json(force=True)
        username = data.get("username", "").strip()
        if not username:
            return jsonify({"success": False, "error": "Username cannot be empty"}), 400

        b64_data = data.get("credential") or data.get("credential_base64")
        if b64_data:
            raw_bytes = base64.b64decode(b64_data)
            elements = parse(raw_bytes)
        else:
            elements_data = data.get("elements", [])
            elements = parse_elements_from_json(elements_data)

        # Enforce size policy (§7.1)
        policy = Policy(max_encoded_bits=160_000_000, max_blob_bits=160_000_000, max_elements=5000)
        builder = CredentialBuilder(policy)
        for el in elements:
            if isinstance(el, Char):
                builder.add_text(el.value)
            elif isinstance(el, Blob):
                builder.add_blob(el.data)
        finalized_elements = builder.finalize()

        # Derive Argon2id verifier (§8.3, §10.1)
        # Default is OWASP Production (64 MiB, t=3, p=1); fast_mode enables 256 KiB testing.
        fast_mode = bool(data.get("fast_mode", False))
        params = AuthParams.fast_testing() if fast_mode else AuthParams.default()
        record = enroll(finalized_elements, params)

        record_json = record.to_json()
        record_bytes_len = len(record_json.encode("utf-8"))

        # Save to SQLite (§9)
        with get_db() as conn:
            try:
                cursor = conn.execute(
                    "INSERT INTO users (username, credential_record) VALUES (?, ?)",
                    (username, record_json),
                )
                conn.commit()
                user_id = cursor.lastrowid
            except sqlite3.IntegrityError:
                return jsonify({"success": False, "error": f"Username '{username}' already exists"}), 409

        return jsonify({
            "success": True,
            "message": f"User '{username}' registered successfully!",
            "user_id": user_id,
            "username": username,
            "stored_record": json.loads(record_json),
            "storage_size_bytes": record_bytes_len,
            "element_count": len(finalized_elements),
            "params": {
                "memory_cost_kib": params.memory_cost_kib,
                "iterations": params.iterations,
                "parallelism": params.parallelism,
            },
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    """
    Authenticate a user (§10.2).
    Receives: { username: str, credential_base64?: str, elements?: list }
    Validates against stored VerifierRecord in SQLite.
    """
    try:
        data = request.get_json(force=True)
        username = data.get("username", "").strip()
        if not username:
            return jsonify({"success": False, "error": "Username cannot be empty"}), 400

        b64_data = data.get("credential") or data.get("credential_base64")
        if b64_data:
            raw_bytes = base64.b64decode(b64_data)
            candidate_elements = parse(raw_bytes)
        else:
            elements_data = data.get("elements", [])
            candidate_elements = parse_elements_from_json(elements_data)

        # 1. Fetch stored record from SQLite
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, credential_record, created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()

        if not row:
            # Generic response to prevent user enumeration (§13.4)
            return jsonify({
                "success": False,
                "status": "DENIED",
                "message": "Invalid username or credential.",
            }), 401

        stored_record = VerifierRecord.from_json(row["credential_record"])

        # 2. Verify candidate credential (§10.2)
        limits = ResourceLimits.default()
        result = verify(candidate_elements, stored_record, limits)

        if result == VerifyResult.OK:
            return jsonify({
                "success": True,
                "status": "OK",
                "message": f"Authentication successful! Welcome, {username}.",
                "user": {
                    "id": row["id"],
                    "username": row["username"],
                    "created_at": row["created_at"],
                },
            })
        else:
            return jsonify({
                "success": False,
                "status": "DENIED",
                "message": "Invalid credential. Access denied.",
            }), 401

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/database", methods=["GET"])
def api_database():
    """
    Live database inspector.
    Returns all rows in SQLite to prove stored record size and structure.
    """
    with get_db() as conn:
        rows = conn.execute("SELECT id, username, credential_record, created_at FROM users ORDER BY id DESC").fetchall()

    users_list = []
    for r in rows:
        record_str = r["credential_record"]
        users_list.append({
            "id": r["id"],
            "username": r["username"],
            "created_at": r["created_at"],
            "record": json.loads(record_str),
            "size_bytes": len(record_str.encode("utf-8")),
        })

    return jsonify({
        "success": True,
        "count": len(users_list),
        "users": users_list,
        "database_file": str(DB_PATH),
    })


@app.route("/api/database/delete", methods=["POST"])
def api_delete_user():
    """Delete a user by id."""
    data = request.get_json(force=True)
    user_id = data.get("id")
    if not user_id:
        return jsonify({"success": False, "error": "User ID required"}), 400

    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

    return jsonify({"success": True, "message": f"User {user_id} deleted."})


@app.route("/api/database/reset", methods=["POST"])
def api_reset_db():
    """Reset the database for testing."""
    with get_db() as conn:
        conn.execute("DELETE FROM users")
        conn.commit()
    return jsonify({"success": True, "message": "Database reset: all users cleared."})


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print(f"\n==================================================")
    print(f"🚀 Mosaic Credential Full-Stack Auth Server running!")
    print(f"👉 Local URL: http://localhost:{port}")
    print(f"📁 SQLite DB: {DB_PATH}")
    print(f"==================================================\n")
    app.run(host="0.0.0.0", port=port, debug=False)
