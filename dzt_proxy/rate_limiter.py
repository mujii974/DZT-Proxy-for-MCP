# dzt_proxy/rate_limiter.py
"""
Simple in-memory rate limiter for the DZT Proxy.

Limits the number of requests per DID per time window.
This prevents brute-force attacks and token-guessing attempts.

Uses a sliding window counter approach with automatic cleanup.
"""

import time
import threading
from collections import defaultdict
from typing import Tuple

# ── Configuration ────────────────────────────────────────────
MAX_REQUESTS_PER_WINDOW = 200  # max requests per DID per window
WINDOW_SECONDS = 60            # sliding window size
CLEANUP_INTERVAL = 120         # how often to purge old entries

# ── State ────────────────────────────────────────────────────
_requests: dict = defaultdict(list)  # did -> [timestamp, ...]
_lock = threading.Lock()
_last_cleanup = 0.0


def _cleanup():
    """Remove expired timestamps from all DIDs."""
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    cutoff = now - WINDOW_SECONDS
    stale_dids = []
    for did, timestamps in _requests.items():
        _requests[did] = [t for t in timestamps if t > cutoff]
        if not _requests[did]:
            stale_dids.append(did)
    for did in stale_dids:
        del _requests[did]


def check_rate_limit(agent_did: str) -> Tuple[bool, str]:
    """
    Check if the agent is within rate limits.

    Returns:
        (allowed: bool, reason: str)
    """
    now = time.time()
    cutoff = now - WINDOW_SECONDS

    with _lock:
        _cleanup()

        # Filter out expired timestamps
        timestamps = [t for t in _requests[agent_did] if t > cutoff]
        _requests[agent_did] = timestamps

        if len(timestamps) >= MAX_REQUESTS_PER_WINDOW:
            return False, f"Rate limit exceeded for {agent_did}: {len(timestamps)}/{MAX_REQUESTS_PER_WINDOW} per {WINDOW_SECONDS}s"

        # Record this request
        _requests[agent_did].append(now)
        return True, "OK"


def get_usage(agent_did: str) -> dict:
    """Get current rate limit usage for a DID (for debugging)."""
    now = time.time()
    cutoff = now - WINDOW_SECONDS
    with _lock:
        timestamps = [t for t in _requests.get(agent_did, []) if t > cutoff]
    return {
        "did": agent_did,
        "requests_in_window": len(timestamps),
        "max_requests": MAX_REQUESTS_PER_WINDOW,
        "window_seconds": WINDOW_SECONDS,
    }
