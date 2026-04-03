# dzt_proxy/nonce_store.py
"""
Replay protection via nonce (jti) tracking.

Stores seen JTI values with their expiry timestamps in SQLite.
Includes automatic cleanup of expired entries to prevent unbounded growth.
"""

import sqlite3
import time
from pathlib import Path

DB = Path("nonces.db")

# How often to run cleanup (seconds). Every 60 seconds at most.
_CLEANUP_INTERVAL = 60
_last_cleanup = 0.0


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            jti     TEXT PRIMARY KEY,
            exp_at  INTEGER NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_nonces_exp ON nonces(exp_at)")
    conn.commit()
    conn.close()


def _maybe_cleanup():
    """Remove nonces that have expired (token can no longer be replayed)."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    deleted = cur.execute("DELETE FROM nonces WHERE exp_at < ?", (int(now),)).rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        from dzt_proxy.audit import audit_log
        audit_log.request_received("NONCE_CLEANUP", f"purged={deleted}")


def seen_before(jti: str) -> bool:
    _maybe_cleanup()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM nonces WHERE jti=?", (jti,))
    row = cur.fetchone()
    conn.close()
    return row is not None


def store_nonce(jti: str, exp_at: int = 0):
    """
    Record a nonce. exp_at should be the JWT's exp claim so we know
    when it's safe to purge. Defaults to now + 600s if not provided.
    """
    if exp_at <= 0:
        exp_at = int(time.time()) + 600
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO nonces (jti, exp_at) VALUES (?, ?)", (jti, exp_at))
    conn.commit()
    conn.close()


def nonce_count() -> int:
    """Return the number of stored nonces (useful for diagnostics)."""
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM nonces")
    count = cur.fetchone()[0]
    conn.close()
    return count
