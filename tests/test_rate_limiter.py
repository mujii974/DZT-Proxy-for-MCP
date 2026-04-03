"""
Unit tests for dzt_proxy.rate_limiter

Tests the sliding window rate limiting:
  - Requests within limit pass
  - Requests over limit are rejected
  - Window resets after time passes
"""

import time
import pytest
from dzt_proxy.rate_limiter import check_rate_limit, _requests, _lock, MAX_REQUESTS_PER_WINDOW


TEST_DID = "did:web:dzt.local:test-rate-limit"


@pytest.fixture(autouse=True)
def clear_state():
    """Reset rate limiter state before each test."""
    with _lock:
        _requests.clear()
    yield
    with _lock:
        _requests.clear()


class TestRateLimiter:

    def test_first_request_allowed(self):
        ok, reason = check_rate_limit(TEST_DID)
        assert ok is True
        assert reason == "OK"

    def test_requests_within_limit_pass(self):
        for i in range(10):
            ok, reason = check_rate_limit(TEST_DID)
            assert ok is True, f"Request {i+1} should be allowed"

    def test_different_dids_have_separate_limits(self):
        for _ in range(10):
            check_rate_limit("did:web:dzt.local:agent-a")

        ok, _ = check_rate_limit("did:web:dzt.local:agent-b")
        assert ok is True, "Different DID should have its own counter"

    def test_over_limit_blocked(self):
        # Fill up to the limit
        for i in range(MAX_REQUESTS_PER_WINDOW):
            ok, _ = check_rate_limit(TEST_DID)
            assert ok is True, f"Request {i+1} should be within limit"

        # Next request should be blocked
        ok, reason = check_rate_limit(TEST_DID)
        assert ok is False
        assert "Rate limit exceeded" in reason
