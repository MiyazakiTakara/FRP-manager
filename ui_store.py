"""Optional, strictly non-secret UI metadata for FRP tunnels.

State is deliberately separate from frpc.toml and session/audit databases.
The service must have a dedicated private writable state directory; no
directory ownership changes to root-owned FRPC infrastructure files.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3

DEFAULT_DB = "/var/lib/frp-manager/ui/state.db"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,23}\Z")

def location():
    return Path(os.environ.get("FRP_MANAGER_UI_DB", DEFAULT_DB))

def connect():
    db = location()
    if not db.parent.is_dir():
        raise RuntimeError("UI metadata directory not provisioned")
    connection = sqlite3.connect(str(db), timeout=3.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=3000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("""CREATE TABLE IF NOT EXISTS tunnel_meta (
        name TEXT PRIMARY KEY NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '[]',
        maintenance_until TEXT,
        updated_at TEXT NOT NULL,
        actor TEXT NOT NULL
    )""")
    return connection

def validate(name, description, tags, maintenance_until):
    if type(name) is not str or not NAME_RE.fullmatch(name):
        raise ValueError("Invalid tunnel name")
    if type(description) is not str or len(description) > 240:
        raise ValueError("Description must be 0-240 characters")
    if type(tags) is not list or len(tags) > 8 or any(type(t) is not str or not TAG_RE.fullmatch(t) for t in tags) or len(set(tags)) != len(tags):
        raise ValueError("Tags must be 0-8 unique short labels")
    if maintenance_until is not None:
        if type(maintenance_until) is not str or len(maintenance_until) > 40:
            raise ValueError("Invalid maintenance time")
        try:
            stamp = datetime.fromisoformat(maintenance_until.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError()
            seconds = (stamp.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()
            if not 0 < seconds < 31*24*3600:
                raise ValueError()
            maintenance_until = stamp.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            raise ValueError("Maintenance must end within the next 30 days") from None
    return description, tags, maintenance_until

def read(name):
    if not NAME_RE.fullmatch(name):
        raise ValueError("Invalid tunnel name")
    with connect() as db:
        row = db.execute("SELECT description,tags,maintenance_until,updated_at,actor FROM tunnel_meta WHERE name=?", (name,)).fetchone()
    if row is None:
        return {"description": "", "tags": [], "maintenance_until": None, "updated_at": None}
    return {"description": row["description"], "tags": json.loads(row["tags"]),
            "maintenance_until": row["maintenance_until"], "updated_at": row["updated_at"]}

def update(name, description, tags, maintenance_until, actor):
    description, tags, maintenance_until = validate(name, description, tags, maintenance_until)
    if type(actor) is not str or not actor or len(actor) > 160:
        raise ValueError("Invalid actor")
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with connect() as db:
        db.execute("""INSERT INTO tunnel_meta(name,description,tags,maintenance_until,updated_at,actor)
        VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET
        description=excluded.description,tags=excluded.tags,
        maintenance_until=excluded.maintenance_until,updated_at=excluded.updated_at,actor=excluded.actor""",
        (name, description, json.dumps(tags), maintenance_until, stamp, actor))
    return read(name)

def list_all():
    with connect() as db:
        rows = db.execute("SELECT name,description,tags,maintenance_until,updated_at FROM tunnel_meta").fetchall()
    return {r["name"]: {"description": r["description"],"tags": json.loads(r["tags"]),
                        "maintenance_until": r["maintenance_until"],"updated_at": r["updated_at"]} for r in rows}
