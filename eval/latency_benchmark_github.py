#!/usr/bin/env python3
"""
Latency Benchmark (GitHub) -- Direct GitHub MCP vs DZT Proxy (GitHub mode).

Measures end-to-end latency for identical legitimate get_me requests:
  1) Direct to GitHub MCP with PAT
  2) Through DZT Proxy (which then forwards to GitHub MCP)

Outputs average, p95, and overhead (proxy - direct) in milliseconds.
"""

import os
import sys
import time
import uuid
import json
import shutil
import subprocess
import tempfile
import statistics
from pathlib import Path
from typing import List

import requests
import jwt as pyjwt
from dotenv import load_dotenv

load_dotenv()

AGENT_DID = os.getenv("AGENT_DID", "did:web:dzt.local:agent1")
SERVER_DID = os.getenv("SERVER_DID", "did:web:dzt.local:mcpserver")
ALGORITHM = os.getenv("JWT_ALG", "ES256K")
GITHUB_PAT = os.getenv("GITHUB_PAT", "")
GITHUB_MCP_URL = os.getenv("GITHUB_MCP_URL", "https://api.githubcopilot.com/mcp/")
PROXY_URL = "http://127.0.0.1:8000"

_key_path = os.getenv("AGENT_PRIVATE_KEY_PATH", "did/keys/agent1_private.pem")
if not Path(_key_path).exists():
    _key_path = "agent1_private.pem"
PRIVATE_KEY = Path(_key_path).read_text(encoding="utf-8") if Path(_key_path).exists() else ""

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
WARMUP = 2


def percentile(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] * (c - k) + s[c] * (k - f)


def github_direct_call() -> float:
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": "get_me", "arguments": {}},
    }
    headers = {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    t0 = time.perf_counter()
    r = requests.post(GITHUB_MCP_URL, headers=headers, json=payload, timeout=30)
    latency = (time.perf_counter() - t0) * 1000.0
    if r.status_code >= 400:
        return -1.0
    return latency


def github_direct_call_breakdown() -> tuple[float, float]:
    """Return (total_ms, server_elapsed_ms) for one direct GitHub request."""
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": "get_me", "arguments": {}},
    }
    headers = {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    t0 = time.perf_counter()
    r = requests.post(GITHUB_MCP_URL, headers=headers, json=payload, timeout=30)
    total_ms = (time.perf_counter() - t0) * 1000.0
    server_elapsed_ms = r.elapsed.total_seconds() * 1000.0
    if r.status_code >= 400:
        return -1.0, -1.0
    return total_ms, server_elapsed_ms


def get_tool_hash() -> str:
    r = requests.get(f"{PROXY_URL}/debug/tool-hash/get_me", timeout=10)
    r.raise_for_status()
    return r.json()["hash"]


def mint(tool_hash: str) -> str:
    now = int(time.time())
    payload = {
        "iss": AGENT_DID,
        "aud": SERVER_DID,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "tool": "get_me",
        "tool_hash": tool_hash,
    }
    return pyjwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)


def github_proxy_call(tool_hash: str) -> float:
    token = mint(tool_hash)
    t0 = time.perf_counter()
    r = requests.post(
        f"{PROXY_URL}/tools/call",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"tool": "get_me", "params": {}},
        timeout=45,
    )
    latency = (time.perf_counter() - t0) * 1000.0
    if r.status_code >= 400:
        return -1.0
    return latency


def github_proxy_call_breakdown(tool_hash: str) -> tuple[float, float, float]:
    """Return (jwt_mint_ms, total_ms, server_elapsed_ms) for one proxy request."""
    t_mint = time.perf_counter()
    token = mint(tool_hash)
    jwt_mint_ms = (time.perf_counter() - t_mint) * 1000.0

    t0 = time.perf_counter()
    r = requests.post(
        f"{PROXY_URL}/tools/call",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"tool": "get_me", "params": {}},
        timeout=45,
    )
    total_ms = (time.perf_counter() - t0) * 1000.0
    server_elapsed_ms = r.elapsed.total_seconds() * 1000.0
    if r.status_code >= 400:
        return -1.0, -1.0, -1.0
    return jwt_mint_ms, total_ms, server_elapsed_ms


def curl_timing_snapshot(url: str, headers: dict, payload: dict, timeout_s: int) -> dict:
    """Collect one-shot transport timings from curl for DNS/connect/TLS/TTFB/total."""
    if not shutil.which("curl"):
        return {}

    fd, payload_path = tempfile.mkstemp(prefix="latency_payload_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        format_str = (
            '{"dns_ms":%{time_namelookup},"connect_ms":%{time_connect},'
            '"tls_ms":%{time_appconnect},"ttfb_ms":%{time_starttransfer},'
            '"total_ms":%{time_total}}'
        )

        cmd = [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-X",
            "POST",
            "--max-time",
            str(timeout_s),
            "--data",
            f"@{payload_path}",
            "-w",
            format_str,
            url,
        ]
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0 or not proc.stdout.strip():
            return {}

        out = json.loads(proc.stdout.strip())
        return {
            "dns_ms": round(float(out.get("dns_ms", 0.0)) * 1000.0, 1),
            "connect_ms": round(float(out.get("connect_ms", 0.0)) * 1000.0, 1),
            "tls_ms": round(float(out.get("tls_ms", 0.0)) * 1000.0, 1),
            "ttfb_ms": round(float(out.get("ttfb_ms", 0.0)) * 1000.0, 1),
            "total_ms": round(float(out.get("total_ms", 0.0)) * 1000.0, 1),
        }
    except Exception:
        return {}
    finally:
        try:
            os.remove(payload_path)
        except OSError:
            pass


def main():
    print(f"\n{'='*70}")
    print("  LATENCY BENCHMARK (GITHUB) -- Direct vs Proxy")
    print(f"{'='*70}")
    print(f"  GitHub MCP : {GITHUB_MCP_URL}")
    print(f"  Proxy      : {PROXY_URL}")
    print(f"  Calls      : {N} per target (+ {WARMUP} warmup)")

    if not GITHUB_PAT:
        print("\n  ERROR: Missing GITHUB_PAT in .env")
        return

    try:
        requests.get(f"{PROXY_URL}/health", timeout=3)
    except Exception:
        print(f"\n  ERROR: Proxy not reachable at {PROXY_URL}")
        return

    try:
        tool_hash = get_tool_hash()
    except Exception as e:
        print(f"\n  ERROR: Cannot fetch get_me hash from proxy: {e}")
        return

    print(f"\n  Warming up ({WARMUP} calls each)...")
    for _ in range(WARMUP):
        github_direct_call()
        github_proxy_call(tool_hash)

    print(f"  Measuring GitHub direct latency ({N} calls)...")
    direct_times = []
    for _ in range(N):
        lat = github_direct_call()
        if lat >= 0:
            direct_times.append(lat)

    print(f"  Measuring GitHub proxy latency ({N} calls)...")
    proxy_times = []
    for _ in range(N):
        lat = github_proxy_call(tool_hash)
        if lat >= 0:
            proxy_times.append(lat)

    d_avg = statistics.mean(direct_times) if direct_times else 0
    d_p95 = percentile(direct_times, 95)
    p_avg = statistics.mean(proxy_times) if proxy_times else 0
    p_p95 = percentile(proxy_times, 95)
    o_avg = p_avg - d_avg
    o_p95 = p_p95 - d_p95

    d_total_ms, d_elapsed_ms = github_direct_call_breakdown()
    p_jwt_ms, p_total_ms, p_elapsed_ms = github_proxy_call_breakdown(tool_hash)

    direct_payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": "get_me", "arguments": {}},
    }
    direct_headers = {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    proxy_payload = {"tool": "get_me", "params": {}}
    proxy_headers = {
        "Authorization": f"Bearer {mint(tool_hash)}",
        "Content-Type": "application/json",
    }

    curl_direct = curl_timing_snapshot(GITHUB_MCP_URL, direct_headers, direct_payload, timeout_s=30)
    curl_proxy = curl_timing_snapshot(f"{PROXY_URL}/tools/call", proxy_headers, proxy_payload, timeout_s=45)

    print(f"\n{'='*70}")
    print("  RESULTS")
    print(f"{'='*70}")
    print(f"  {'Metric':<25} {'Direct':>10} {'Proxy':>10} {'Overhead':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}")
    print(f"  {'Avg latency (ms)':<25} {d_avg:>10.1f} {p_avg:>10.1f} {o_avg:>+10.1f}")
    print(f"  {'P95 latency (ms)':<25} {d_p95:>10.1f} {p_p95:>10.1f} {o_p95:>+10.1f}")
    print(f"  {'Success rate':<25} {len(direct_times):>9}/{N} {len(proxy_times):>9}/{N} {'':>10}")

    print(f"\n{'='*70}")
    print("  BREAKDOWN (single-call diagnostics)")
    print(f"{'='*70}")
    if d_total_ms >= 0:
        d_client_ms = max(0.0, d_total_ms - d_elapsed_ms)
        print(f"  Direct call total (ms)          : {d_total_ms:.1f}")
        print(f"  Direct response elapsed (ms)    : {d_elapsed_ms:.1f}")
        print(f"  Direct client overhead (ms)     : {d_client_ms:.1f}")
    if p_total_ms >= 0:
        p_client_ms = max(0.0, p_total_ms - p_elapsed_ms)
        print(f"  Proxy JWT mint (ms)             : {p_jwt_ms:.2f}")
        print(f"  Proxy call total (ms)           : {p_total_ms:.1f}")
        print(f"  Proxy response elapsed (ms)     : {p_elapsed_ms:.1f}")
        print(f"  Proxy client overhead (ms)      : {p_client_ms:.1f}")

    if curl_direct:
        print("\n  Curl transport snapshot (Direct GitHub)")
        print(f"    DNS lookup (ms)               : {curl_direct['dns_ms']:.1f}")
        print(f"    TCP connect (ms)              : {curl_direct['connect_ms']:.1f}")
        print(f"    TLS handshake (ms)            : {curl_direct['tls_ms']:.1f}")
        print(f"    Time to first byte (ms)       : {curl_direct['ttfb_ms']:.1f}")
        print(f"    Total curl time (ms)          : {curl_direct['total_ms']:.1f}")
    if curl_proxy:
        print("\n  Curl transport snapshot (Proxy endpoint)")
        print(f"    DNS lookup (ms)               : {curl_proxy['dns_ms']:.1f}")
        print(f"    TCP connect (ms)              : {curl_proxy['connect_ms']:.1f}")
        print(f"    TLS handshake (ms)            : {curl_proxy['tls_ms']:.1f}")
        print(f"    Time to first byte (ms)       : {curl_proxy['ttfb_ms']:.1f}")
        print(f"    Total curl time (ms)          : {curl_proxy['total_ms']:.1f}")

    print("")
    if o_avg < 50:
        print(f"  RESULT: Proxy overhead ({o_avg:+.1f} ms avg) is below 50ms target")
    else:
        print(f"  RESULT: Proxy overhead ({o_avg:+.1f} ms avg) EXCEEDS 50ms target")

    print("  Note: GitHub absolute latency can be high due to internet + remote service time.")
    print("  For proxy efficiency, evaluate overhead (proxy - direct), not absolute latency alone.")

    out_dir = Path("eval/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"latency_benchmark_github_{int(time.time())}.json"
    out = {
        "test": "latency_benchmark_github",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "calls_per_target": N,
        "warmup": WARMUP,
        "direct": {
            "success": len(direct_times),
            "avg_ms": round(d_avg, 1),
            "p95_ms": round(d_p95, 1),
        },
        "proxy": {
            "success": len(proxy_times),
            "avg_ms": round(p_avg, 1),
            "p95_ms": round(p_p95, 1),
        },
        "overhead": {
            "avg_ms": round(o_avg, 1),
            "p95_ms": round(o_p95, 1),
        },
        "breakdown": {
            "direct_single_call": {
                "total_ms": round(d_total_ms, 1) if d_total_ms >= 0 else None,
                "response_elapsed_ms": round(d_elapsed_ms, 1) if d_elapsed_ms >= 0 else None,
                "client_overhead_ms": round(max(0.0, d_total_ms - d_elapsed_ms), 1) if d_total_ms >= 0 and d_elapsed_ms >= 0 else None,
            },
            "proxy_single_call": {
                "jwt_mint_ms": round(p_jwt_ms, 3) if p_jwt_ms >= 0 else None,
                "total_ms": round(p_total_ms, 1) if p_total_ms >= 0 else None,
                "response_elapsed_ms": round(p_elapsed_ms, 1) if p_elapsed_ms >= 0 else None,
                "client_overhead_ms": round(max(0.0, p_total_ms - p_elapsed_ms), 1) if p_total_ms >= 0 and p_elapsed_ms >= 0 else None,
            },
            "curl_transport": {
                "direct": curl_direct or None,
                "proxy": curl_proxy or None,
            },
        },
    }
    out_file.write_text(json.dumps(out, indent=2))
    print(f"\n  Results saved: {out_file}\n")


if __name__ == "__main__":
    main()
