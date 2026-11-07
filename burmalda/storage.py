import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .crypto import digest


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Store:
    """One instance opens exactly one role's SQLite file; no attached foreign databases."""
    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, body TEXT NOT NULL, PRIMARY KEY(kind,id));
                CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, meta TEXT, previous TEXT, hash TEXT);
                CREATE TABLE IF NOT EXISTS rpc_cache (id TEXT PRIMARY KEY, fingerprint TEXT, response TEXT);
                CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, envelope TEXT, delivered INTEGER NOT NULL DEFAULT 0);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA secure_delete=ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get(self, kind, identifier, default=None, db=None):
        if db is None:
            with self.connect() as connection:
                return self.get(kind, identifier, default, connection)
        row = db.execute("SELECT body FROM records WHERE kind=? AND id=?", (kind, identifier)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, kind, identifier, body, db=None):
        if db is None:
            with self.connect() as connection:
                return self.put(kind, identifier, body, connection)
        db.execute("INSERT INTO records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", (kind, identifier, json.dumps(body, ensure_ascii=False)))

    def all(self, kind):
        with self.connect() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT body FROM records WHERE kind=? ORDER BY rowid", (kind,))]

    def delete(self, kind, identifier):
        with self.connect() as db:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, identifier))

    def audit(self, event, **metadata):
        # Callers supply metadata only: never arbitrary request/response bodies.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            previous = row[0] if row else "0" * 64
            ts = now()
            hashed = digest({"ts": ts, "action": event, "meta": metadata, "previous": previous})
            db.execute("INSERT INTO audit(ts,action,meta,previous,hash) VALUES(?,?,?,?,?)", (ts, event, json.dumps(metadata, ensure_ascii=False), previous, hashed))

    def audits(self):
        with self.connect() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM audit ORDER BY seq DESC LIMIT 80")]
        for row in rows:
            row["meta"] = json.loads(row["meta"])
        return rows

    def clear(self):
        with self.connect() as db:
            for table in ("records", "audit", "rpc_cache", "outbox"):
                db.execute("DELETE FROM " + table)
