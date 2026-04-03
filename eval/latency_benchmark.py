#!/usr/bin/env python3
"""
Latency Benchmark -- Direct vs Proxy overhead measurement.

Sends N identical legitimate requests to:
  1. Local MCP server directly (no proxy)
  2. Local MCP server through DZT Proxy

Then computes the overhead: proxy_latency - direct_latency.

Report objective: "<50ms latency overhead per call"

All measurements are real round-trip HTTP times, not simulated.
"""

import os
import sys
import time
import uuid
import json
import statistics
from pathlib import Path
from typing import List

import requests
import jwt as pyjwt

from dotenv import load_dotenv
load_dotenv()

# ── Config ────────────────────────────────────────────────────
AGENT_DID = os.getenv("AGENT_DID", "did:web:dzt.local:agent1")
SERVER_DID = os.getenv("SERVER_DID", "did:web:dzt.local:mcpserver")
ALGORITHM = os.getenv("JWT_ALG", "ES256K")

BASELINE_URL = "http://127.0.0.1:8001"
PROXY_URL = "http://127.0.0.1:8000"

_key_path = os.getenv("AGENT_PRIVATE_KEY_PATH", "did/keys/agent1_private.pem")
if not Path(_key_path).exists():
    _key_path = "agent1_private.pem"
PRIVATE_KEY = Path(_key_path).read_text(encoding="utf-8") if Path(_key_path).exists() else ""

N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
WARMUP = 3


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


def call_direct(tool: str, params: dict) -> float:
    """Send directly to baseline server. Returns latency in ms."""
    t0 = time.perf_counter()
    r = requests.post(
        f"{BASELINE_URL}/tools/call",
        json={"tool": tool, "params": params},
        timeout=15,
    )
    latency = (time.perf_counter() - t0) * 1000.0
    if r.status_code >= 400:
        return -1.0
    return latency


def call_proxy(tool: str, params: dict, tool_hash: str) -> float:
    """Send through DZT proxy with fresh JWT. Returns latency in ms."""
    token = mint(tool, tool_hash)
    t0 = time.perf_counter()
    r = requests.post(
        f"{PROXY_URL}/tools/call",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"tool": tool, "params": params},
        timeout=15,
    )
    latency = (time.perf_counter() - t0) * 1000.0
    if r.status_code >= 400:
        return -1.0
    return latency


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] * (c - k) + s[c] * (k - f)


def main():
    tool = "echo"
    params = {"message": "latency benchmark"}

    print(f"\n{'='*70}")
    print(f"  LATENCY BENCHMARK -- Direct vs Proxy")
    print(f"{'='*70}")
    print(f"  Direct   : {BASELINE_URL}")
    print(f"  Proxy    : {PROXY_URL}")
    print(f"  Tool     : {tool}")
    print(f"  Calls    : {N} per target (+ {WARMUP} warmup)")

    # Verify both servers
    try:
        requests.get(f"{BASELINE_URL}/tools", timeout=3)
    except Exception:
        print(f"\n  ERROR: Baseline not reachable at {BASELINE_URL}")
        return

    try:
        requests.get(f"{PROXY_URL}/health", timeout=3)
    except Exception:
        print(f"\n  ERROR: Proxy not reachable at {PROXY_URL}")
        return

    try:
        tool_hash = get_tool_hash(tool)
    except Exception as e:
        print(f"\n  ERROR: Cannot get tool hash: {e}")
        return

    # ── Warmup ───────────────────────────────────────────────
    print(f"\n  Warming up ({WARMUP} calls each)...")
    for _ in range(WARMUP):
        call_direct(tool, params)
        call_proxy(tool, params, tool_hash)

    # ── Direct measurements ──────────────────────────────────
    print(f"  Measuring direct latency ({N} calls)...")
    direct_times = []
    direct_ok = 0
    for i in range(N):
        lat = call_direct(tool, params)
        if lat >= 0:
            direct_times.append(lat)
            direct_ok += 1

    # ── Proxy measurements ───────────────────────────────────
    print(f"  Measuring proxy latency ({N} calls)...")
    proxy_times = []
    proxy_ok = 0
    for i in range(N):
        lat = call_proxy(tool, params, tool_hash)
        if lat >= 0:
            proxy_times.append(lat)
            proxy_ok += 1

    # ── Compute stats ────────────────────────────────────────
    d_avg = statistics.mean(direct_times) if direct_times else 0
    d_p95 = percentile(direct_times, 95)
    d_min = min(direct_times) if direct_times else 0
    d_max = max(direct_times) if direct_times else 0

    p_avg = statistics.mean(proxy_times) if proxy_times else 0
    p_p95 = percentile(proxy_times, 95)
    p_min = min(proxy_times) if proxy_times else 0
    p_max = max(proxy_times) if proxy_times else 0

    overhead_avg = p_avg - d_avg
    overhead_p95 = p_p95 - d_p95

    # ── Print results ────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  RESULTS")
    print(f"{'='*70}")
    print(f"")
    print(f"  {'Metric':<25} {'Direct':>10} {'Proxy':>10} {'Overhead':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}")
    print(f"  {'Avg latency (ms)':<25} {d_avg:>10.1f} {p_avg:>10.1f} {overhead_avg:>+10.1f}")
    print(f"  {'P95 latency (ms)':<25} {d_p95:>10.1f} {p_p95:>10.1f} {overhead_p95:>+10.1f}")
    print(f"  {'Min latency (ms)':<25} {d_min:>10.1f} {p_min:>10.1f} {'':>10}")
    print(f"  {'Max latency (ms)':<25} {d_max:>10.1f} {p_max:>10.1f} {'':>10}")
    print(f"  {'Success rate':<25} {direct_ok:>9}/{N} {proxy_ok:>9}/{N} {'':>10}")

    if overhead_avg < 50:
        print(f"\n  RESULT: Average overhead ({overhead_avg:+.1f} ms) is below 50ms target")
    else:
        print(f"\n  RESULT: Average overhead ({overhead_avg:+.1f} ms) EXCEEDS 50ms target")

    print(f"{'='*70}\n")

    # Save results
    out_dir = Path("eval/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"latency_benchmark_{int(time.time())}.json"
    out_data = {
        "test": "latency_benchmark",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "calls_per_target": N,
        "warmup": WARMUP,
        "tool": tool,
        "direct": {
            "success": direct_ok,
            "avg_ms": round(d_avg, 1),
            "p95_ms": round(d_p95, 1),
            "min_ms": round(d_min, 1),
            "max_ms": round(d_max, 1),
        },
        "proxy": {
            "success": proxy_ok,
            "avg_ms": round(p_avg, 1),
            "p95_ms": round(p_p95, 1),
            "min_ms": round(p_min, 1),
            "max_ms": round(p_max, 1),
        },
        "overhead": {
            "avg_ms": round(overhead_avg, 1),
            "p95_ms": round(overhead_p95, 1),
        },
    }
    out_file.write_text(json.dumps(out_data, indent=2))
    print(f"  Results saved: {out_file}\n")


if __name__ == "__main__":
    main()
