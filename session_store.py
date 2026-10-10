import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

DB_PATH = Path("/var/lib/frp-manager/manager.db")
SESSION_TTL = 1800


def cipher():
    secret = os.environ["SESSION_SECRET"]
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def session_hash(session_id):
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def connect():
    db = sqlite3.connect(str(DB_PATH), timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout=5000")
    return db


def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(DB_PATH.parent, 0o700)

    with closing(connect()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_hash TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                display_name TEXT NOT NULL,
                encrypted_token BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS sessions_expiry
            ON sessions(expires_at);

            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                subject TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                details TEXT
            );
        """)

        columns = {
            row[1] for row in db.execute("PRAGMA table_info(sessions)")
        }
        if "token_expires_at" not in columns:
            db.execute(
                "ALTER TABLE sessions ADD COLUMN token_expires_at INTEGER"
            )
            db.execute(
                "UPDATE sessions SET token_expires_at = expires_at "
                "WHERE token_expires_at IS NULL"
            )

        db.commit()

    with closing(connect()) as db:
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(sessions)")
        }
        if "encrypted_id_token" not in columns:
            db.execute(
                "ALTER TABLE sessions "
                "ADD COLUMN encrypted_id_token BLOB"
            )
            db.commit()

    with closing(connect()) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
        if "encrypted_refresh_token" not in columns:
            db.execute("ALTER TABLE sessions ADD COLUMN encrypted_refresh_token BLOB")
            db.commit()
    os.chmod(DB_PATH, 0o600)


def audit(action, result, subject=None, details=None):
    with closing(connect()) as db:
        db.execute(
            """
            INSERT INTO audit_events
            (created_at, subject, action, result, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(time.time()),
                subject,
                action,
                result,
                json.dumps(details, ensure_ascii=False)
                if details is not None else None,
            ),
        )
        db.commit()


def create_session(
    subject, display_name, access_token, token_expires_at,
    id_token=None, refresh_token=None
):
    now = int(time.time())
    sid = secrets.token_urlsafe(32)
    token_expiry = int(token_expires_at)
    expiry = min(now + SESSION_TTL, token_expiry)

    if expiry <= now:
        raise ValueError("Token already expired")

    encrypted = cipher().encrypt(access_token.encode("utf-8"))
    encrypted_refresh = cipher().encrypt(refresh_token.encode("utf-8")) if refresh_token else None
    encrypted_id = (
        cipher().encrypt(id_token.encode("utf-8"))
        if id_token else None
    )

    with closing(connect()) as db:
        db.execute(
            """
            INSERT INTO sessions (
                session_hash, subject, display_name,
                encrypted_token, encrypted_id_token, encrypted_refresh_token,
                created_at, last_seen, expires_at, token_expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_hash(sid), subject, display_name,
                encrypted, encrypted_id, encrypted_refresh, now, now,
                expiry, token_expiry
            ),
        )
        db.commit()

    return sid


def get_session(session_id):
    if not session_id:
        return None

    now = int(time.time())
    hashed = session_hash(session_id)

    with closing(connect()) as db:
        row = db.execute(
            "SELECT * FROM sessions WHERE session_hash = ?",
            (hashed,),
        ).fetchone()

        if row is None:
            return None

        if row["expires_at"] <= now:
            db.execute(
                "DELETE FROM sessions WHERE session_hash = ?",
                (hashed,),
            )
            db.commit()
            return None

        try:
            token = cipher().decrypt(
                row["encrypted_token"]
            ).decode("utf-8")

            refresh_token = None
            if row["encrypted_refresh_token"]:
                refresh_token = cipher().decrypt(row["encrypted_refresh_token"]).decode("utf-8")
            id_token = None
            if row["encrypted_id_token"]:
                id_token = cipher().decrypt(
                    row["encrypted_id_token"]
                ).decode("utf-8")

        except (InvalidToken, UnicodeDecodeError):
            db.execute(
                "DELETE FROM sessions WHERE session_hash = ?",
                (hashed,),
            )
            db.commit()
            return None

        expiry = now + SESSION_TTL if refresh_token else min(now + SESSION_TTL, row["token_expires_at"])

        db.execute(
            """
            UPDATE sessions
            SET last_seen = ?, expires_at = ?
            WHERE session_hash = ?
            """,
            (now, expiry, hashed),
        )
        db.commit()

        return {
            "sub": row["subject"],
            "name": row["display_name"],
            "access_token": token,
            "refresh_token": refresh_token,
            "token_expires_at": row["token_expires_at"],
            "id_token": id_token,
            "expires": expiry,
        }


def replace_tokens(session_id, access_token, token_expires_at, refresh_token, id_token=None):
    """Atomically rotate encrypted OAuth credentials after Keycloak refresh."""
    now = int(time.time())
    encrypted_access = cipher().encrypt(access_token.encode("utf-8"))
    encrypted_refresh = cipher().encrypt(refresh_token.encode("utf-8")) if refresh_token else None
    encrypted_id = cipher().encrypt(id_token.encode("utf-8")) if id_token else None
    with closing(connect()) as db:
        db.execute(
            """UPDATE sessions SET encrypted_token=?, token_expires_at=?,
               encrypted_refresh_token=?, encrypted_id_token=?, expires_at=?, last_seen=?
               WHERE session_hash=?""",
            (encrypted_access, int(token_expires_at), encrypted_refresh, encrypted_id,
             now + SESSION_TTL, now, session_hash(session_id)))
        db.commit()


def revoke_session(session_id):
    if not session_id:
        return

    with closing(connect()) as db:
        db.execute(
            "DELETE FROM sessions WHERE session_hash = ?",
            (session_hash(session_id),),
        )
        db.commit()


def cleanup():
    with closing(connect()) as db:
        db.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (int(time.time()),),
        )
        db.commit()
