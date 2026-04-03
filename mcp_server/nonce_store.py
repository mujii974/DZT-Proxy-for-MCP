# mcp_server/nonce_store.py
"""Replay protection for the MCP server (server-side)."""

import sqlite3
import time
from pathlib import Path

DB = Path("server_nonces.db")

_CLEANUP_INTERVAL = 60
_last_cleanup = 0.0


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            jti    TEXT PRIMARY KEY,
            exp_at INTEGER NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_nonces_exp ON nonces(exp_at)")
    conn.commit()
    conn.close()


def _maybe_cleanup():
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < _CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM nonces WHERE exp_at < ?", (int(now),))
    conn.commit()
    conn.close()


def seen_before(jti: str) -> bool:
    _maybe_cleanup()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM nonces WHERE jti=?", (jti,))
    row = cur.fetchone()
    conn.close()
    return row is not None


def store_nonce(jti: str, exp_at: int = 0):
    if exp_at <= 0:
        exp_at = int(time.time()) + 600
    conn = sqlite3.connect(DB)
    conn.execute("INSERT OR IGNORE INTO nonces (jti, exp_at) VALUES (?, ?)", (jti, exp_at))
    conn.commit()
    conn.close()
