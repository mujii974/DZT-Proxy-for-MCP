"""
Unit tests for dzt_proxy.nonce_store

Tests replay protection via JTI tracking:
  - Fresh nonces are not seen before
  - Stored nonces ARE seen before (replay detection)
  - Multiple nonces are tracked independently
  - TTL cleanup removes expired entries
  - Nonce count reporting
"""

import os
import time
import uuid
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch

# Use a test-specific database file
TEST_DB = Path("/tmp/test_nonces.db")


@pytest.fixture(autouse=True)
def clean_db():
    """Ensure a fresh database for each test."""
    if TEST_DB.exists():
        TEST_DB.unlink()

    # Patch the DB path
    import dzt_proxy.nonce_store as ns
    original_db = ns.DB
    ns.DB = TEST_DB
    ns._last_cleanup = 0.0
    ns.init_db()

    yield

    ns.DB = original_db
    if TEST_DB.exists():
        TEST_DB.unlink()


class TestBasicReplay:

    def test_fresh_nonce_not_seen(self):
        from dzt_proxy.nonce_store import seen_before
        jti = str(uuid.uuid4())
        assert not seen_before(jti)

    def test_stored_nonce_is_seen(self):
        from dzt_proxy.nonce_store import seen_before, store_nonce
        jti = str(uuid.uuid4())
        store_nonce(jti, int(time.time()) + 600)
        assert seen_before(jti)

    def test_different_nonces_independent(self):
        from dzt_proxy.nonce_store import seen_before, store_nonce
        jti1 = str(uuid.uuid4())
        jti2 = str(uuid.uuid4())

        store_nonce(jti1, int(time.time()) + 600)

        assert seen_before(jti1)
        assert not seen_before(jti2)

    def test_duplicate_insert_is_idempotent(self):
        from dzt_proxy.nonce_store import store_nonce, seen_before
        jti = str(uuid.uuid4())
        store_nonce(jti, int(time.time()) + 600)
        store_nonce(jti, int(time.time()) + 600)  # should not raise
        assert seen_before(jti)


class TestNonceCount:

    def test_count_starts_at_zero(self):
        from dzt_proxy.nonce_store import nonce_count
        assert nonce_count() == 0

    def test_count_increments(self):
        from dzt_proxy.nonce_store import store_nonce, nonce_count
        for i in range(5):
            store_nonce(str(uuid.uuid4()), int(time.time()) + 600)
        assert nonce_count() == 5


class TestTTLCleanup:

    def test_expired_nonces_cleaned(self):
        from dzt_proxy.nonce_store import store_nonce, seen_before, nonce_count
        import dzt_proxy.nonce_store as ns

        # Store a nonce that's already expired
        expired_jti = str(uuid.uuid4())
        store_nonce(expired_jti, int(time.time()) - 10)

        # Store a nonce that's still valid
        valid_jti = str(uuid.uuid4())
        store_nonce(valid_jti, int(time.time()) + 600)

        assert nonce_count() == 2

        # Force cleanup by resetting the interval timer
        ns._last_cleanup = 0.0
        ns._CLEANUP_INTERVAL = 0  # force cleanup on next call

        # Trigger cleanup via seen_before
        seen_before("trigger-cleanup")

        # Expired nonce should be gone, valid one should remain
        assert not seen_before(expired_jti)
        assert seen_before(valid_jti)
        assert nonce_count() == 1

        # Restore
        ns._CLEANUP_INTERVAL = 60
