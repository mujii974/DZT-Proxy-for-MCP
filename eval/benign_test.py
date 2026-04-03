#!/usr/bin/env python3
"""
Benign Workload Test -- False Positive Rate measurement.

Sends 100+ legitimate, correctly-signed requests through the DZT Proxy
and counts how many get incorrectly blocked (false positives).

Report objective: "<1% false positive rate across 100+ benign tool calls"

Every call uses a fresh JWT with a unique jti, correct tool_hash,
valid audience, and valid issuer. If ANY of these get blocked,
that is a false positive -- the proxy incorrectly rejected a valid request.
"""

import os
import sys
import time
import uuid
import json
import statistics
from pathlib import Path
from typing import Dict, Any

import requests
import jwt as pyjwt

from dotenv import load_dotenv
load_dotenv()

# ── Config ────────────────────────────────────────────────────
AGENT_DID = os.getenv("AGENT_DID", "did:web:dzt.local:agent1")
SERVER_DID = os.getenv("SERVER_DID", "did:web:dzt.local:mcpserver")
ALGORITHM = os.getenv("JWT_ALG", "ES256K")
PROXY_URL = "http://127.0.0.1:8000"

_key_path = os.getenv("AGENT_PRIVATE_KEY_PATH", "did/keys/agent1_private.pem")
if not Path(_key_path).exists():
    _key_path = "agent1_private.pem"
PRIVATE_KEY = Path(_key_path).read_text(encoding="utf-8") if Path(_key_path).exists() else ""

MODE = os.getenv("UPSTREAM_MODE", "local").lower()
N = int(sys.argv[1]) if len(sys.argv) > 1 else 100


def get_tool_hash(tool: str) -> str:
    r = requests.get(f"{PROXY_URL}/debug/tool-hash/{tool}", timeout=10)
    r.raise_for_status()
    return r.json()["hash"]


def mint(tool: str, tool_hash: str) -> str:
    now = int(time.time())
    payload = {
        "iss": AGENT_DID,
        "aud": SERVER_DID,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "tool": tool,
        "tool_hash": tool_hash,
    }
    return pyjwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)


def call_once(tool: str, params: dict, tool_hash: str):
    """Send one legitimate request. Returns (success, status, latency_ms)."""
    token = mint(tool, tool_hash)
    t0 = time.perf_counter()
    r = requests.post(
        f"{PROXY_URL}/tools/call",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"tool": tool, "params": params},
        timeout=30,
    )
    latency = (time.perf_counter() - t0) * 1000.0
    return r.status_code < 400, r.status_code, latency


def main():
    tool = "get_me" if MODE == "github" else "echo"
    params = {} if MODE == "github" else {"message": "benign test"}

    print(f"\n{'='*70}")
    print(f"  BENIGN WORKLOAD TEST -- False Positive Rate")
    print(f"{'='*70}")
    print(f"  Proxy  : {PROXY_URL}")
    print(f"  Tool   : {tool}")
    print(f"  Calls  : {N}")
    print(f"  Mode   : {MODE}")

    # Verify proxy is up
    try:
        requests.get(f"{PROXY_URL}/health", timeout=3)
    except Exception:
        print(f"\n  ERROR: Proxy not reachable at {PROXY_URL}")
        return

    # Get tool hash once
    try:
        tool_hash = get_tool_hash(tool)
    except Exception as e:
        print(f"\n  ERROR: Cannot get tool hash: {e}")
        return

    print(f"\n  Running {N} benign calls...\n")

    successes = 0
    failures = 0
    latencies = []
    status_counts: Dict[int, int] = {}

    for i in range(N):
        ok, status, latency = call_once(tool, params, tool_hash)
        if ok:
            successes += 1
        else:
            failures += 1
        latencies.append(latency)
        status_counts[status] = status_counts.get(status, 0) + 1

        if (i + 1) % 20 == 0:
            print(f"    {i+1}/{N} completed...")

    # ── Results ──────────────────────────────────────────────
    fp_rate = (failures / N) * 100.0
    success_rate = (successes / N) * 100.0
    avg_lat = statistics.mean(latencies)
    p95_lat = sorted(latencies)[int(0.95 * (len(latencies) - 1))] if latencies else 0
    min_lat = min(latencies) if latencies else 0
    max_lat = max(latencies) if latencies else 0

    print(f"\n{'='*70}")
    print(f"  RESULTS")
    print(f"{'='*70}")
    print(f"  Total calls      : {N}")
    print(f"  Succeeded        : {successes}")
    print(f"  Blocked (FP)     : {failures}")
    print(f"  False positive % : {fp_rate:.2f}%")
    print(f"  Success rate %   : {success_rate:.2f}%")
    print(f"  Avg latency      : {avg_lat:.1f} ms")
    print(f"  P95 latency      : {p95_lat:.1f} ms")
    print(f"  Min latency      : {min_lat:.1f} ms")
    print(f"  Max latency      : {max_lat:.1f} ms")
    print(f"  Status codes     : {status_counts}")

    if fp_rate < 1.0:
        print(f"\n  RESULT: False positive rate ({fp_rate:.2f}%) is below 1% target")
    else:
        print(f"\n  RESULT: False positive rate ({fp_rate:.2f}%) EXCEEDS 1% target")

    print(f"{'='*70}\n")

    # Save results
    out_dir = Path("eval/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"benign_test_{int(time.time())}.json"
    out_data = {
        "test": "benign_workload",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": MODE,
        "tool": tool,
        "total_calls": N,
        "successes": successes,
        "failures": failures,
        "false_positive_rate_pct": round(fp_rate, 2),
        "success_rate_pct": round(success_rate, 2),
        "avg_latency_ms": round(avg_lat, 1),
        "p95_latency_ms": round(p95_lat, 1),
        "min_latency_ms": round(min_lat, 1),
        "max_latency_ms": round(max_lat, 1),
        "status_counts": status_counts,
    }
    out_file.write_text(json.dumps(out_data, indent=2))
    print(f"  Results saved: {out_file}\n")


if __name__ == "__main__":
    main()
