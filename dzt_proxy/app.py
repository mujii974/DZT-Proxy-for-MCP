# dzt_proxy/app.py
"""
DZT Proxy — Decentralized Zero-Trust Proxy for MCP.

This FastAPI application sits between MCP clients (LLM agents) and MCP servers.
It enforces continuous cryptographic verification on every tool call:

    1. JWT presence and structure
    2. DID-based issuer resolution
    3. Signature verification + expiry + audience
    4. Tool binding (JWT tool claim == request tool)
    5. Replay protection (jti nonce)
    6. Rate limiting (per-DID sliding window)
    7. Policy enforcement (per-DID allowlist)
    8. Tool integrity (SHA-256 hash match)

Two modes:
    DZT_MODE=secure   — all checks enforced (default)
    DZT_MODE=baseline — checks skipped, for "before DZT" comparison
"""

import time
import uuid
import os
import logging

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx

from dotenv import load_dotenv
load_dotenv()

from dzt_proxy.did_resolver import get_public_key_pem
from dzt_proxy.config import SERVER_DID
from dzt_proxy.jwt_utils import verify_token, get_unverified_claims
from dzt_proxy.nonce_store import init_db, seen_before, store_nonce
from dzt_proxy.policy import is_allowed
from dzt_proxy.tool_registry import get_tool_hash, fetch_tool_specs, invalidate_cache
from dzt_proxy.sse import extract_first_sse_json
from dzt_proxy.audit import audit_log
from dzt_proxy.rate_limiter import check_rate_limit

logger = logging.getLogger("dzt.proxy")

app = FastAPI(title="DZT Proxy", version="1.0.0")


@app.on_event("startup")
def _startup():
    init_db()
    invalidate_cache()
    mode = os.getenv("DZT_MODE", "secure").lower()
    logger.info("DZT Proxy starting — mode=%s, upstream=%s", mode, os.getenv("UPSTREAM_MODE", "github"))


# ── Utility endpoints ────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "mode": os.getenv("DZT_MODE", "secure")}


@app.get("/tools")
async def proxy_list_tools():
    return await fetch_tool_specs()


@app.get("/debug/env")
def debug_env():
    v = os.getenv("GITHUB_PAT")
    return {
        "has_GITHUB_PAT": bool(v),
        "len": len(v) if v else 0,
        "DZT_MODE": os.getenv("DZT_MODE", "secure"),
        "UPSTREAM_MODE": os.getenv("UPSTREAM_MODE", "github"),
    }


@app.get("/debug/tool-hash/{tool_name}")
async def debug_tool_hash(tool_name: str):
    try:
        h = await get_tool_hash(tool_name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
    return {"tool": tool_name, "hash": h}


# ── Structured error responses ───────────────────────────────

def _deny(status: int, reason: str, stage: str, agent_did: str = "unknown", tool: str = "unknown") -> JSONResponse:
    """
    Return a structured JSON error and log the denial.
    Every rejection includes machine-readable fields so eval scripts
    can validate the specific defense that triggered.
    """
    audit_log.verification_failed(agent_did, tool, reason, stage)
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error": reason,
            "blocked_by": stage,
            "agent_did": agent_did,
            "tool": tool,
        },
    )


# ── Upstream forwarding ──────────────────────────────────────

async def _forward_local(tool: str, params: dict, token: str = None) -> dict:
    """Forward to local MCP server."""
    from dzt_proxy.config import LOCAL_MCP_TOOLS_CALL_URL
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient() as client:
        r = await client.post(
            LOCAL_MCP_TOOLS_CALL_URL,
            headers=headers,
            json={"tool": tool, "params": params},
            timeout=30,
        )
        r.raise_for_status()
        return r.json()


async def _forward_github(tool: str, params: dict) -> dict:
    """Forward to GitHub Copilot MCP via JSON-RPC SSE."""
    from dzt_proxy.config import GITHUB_MCP_URL, GITHUB_PAT
    if not GITHUB_PAT:
        raise HTTPException(status_code=502, detail="Missing GITHUB_PAT — cannot reach GitHub MCP")

    rpc_payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "tools/call",
        "params": {"name": tool, "arguments": params},
    }

    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(
                GITHUB_MCP_URL,
                headers={
                    "Authorization": f"Bearer {GITHUB_PAT}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json=rpc_payload,
                timeout=30,
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Cannot reach GitHub MCP: {e}")

        if r.status_code == 401:
            raise HTTPException(status_code=502, detail="GitHub MCP rejected the PAT — check GITHUB_PAT in .env")
        if r.status_code >= 400:
            raise HTTPException(status_code=502, detail=f"GitHub MCP returned {r.status_code}: {r.text[:200]}")

        return extract_first_sse_json(r.text)


async def _forward_upstream(tool: str, params: dict, token: str = None) -> dict:
    """Route to the appropriate upstream based on UPSTREAM_MODE."""
    from dzt_proxy.config import upstream_mode as get_mode
    mode = get_mode()
    if mode == "local":
        return await _forward_local(tool, params, token)
    return await _forward_github(tool, params)


# ── Main tool-call endpoint ──────────────────────────────────

@app.post("/tools/call")
async def proxy_tool_call(request: Request):
    dzt_mode = os.getenv("DZT_MODE", "secure").lower()

    # ═══════════════════════════════════════════════════════════
    # BASELINE MODE — no security, for "before DZT" comparison
    # ═══════════════════════════════════════════════════════════
    if dzt_mode == "baseline":
        body = await request.json()
        requested_tool = body.get("tool")
        params = body.get("params", {}) or {}

        if not requested_tool:
            raise HTTPException(status_code=400, detail="Missing tool in request body")

        audit_log.baseline_passthrough(requested_tool, note="no security checks")

        t0 = time.perf_counter()
        result = await _forward_upstream(requested_tool, params)
        elapsed = (time.perf_counter() - t0) * 1000
        audit_log.request_forwarded("baseline", requested_tool, dzt_mode, 200, elapsed)
        return result

    # ═══════════════════════════════════════════════════════════
    # SECURE MODE — full DZT verification pipeline
    # ═══════════════════════════════════════════════════════════
    check_start = time.perf_counter()

    # ── Step 1: Require Bearer token ─────────────────────────
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        return _deny(401, "Missing Bearer token", "token_presence")
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return _deny(401, "Empty Bearer token", "token_presence")

    # ── Step 2: Decode issuer DID (unverified) ───────────────
    try:
        unverified = get_unverified_claims(token)
    except Exception:
        return _deny(401, "Malformed JWT: cannot decode claims", "jwt_decode")

    iss = unverified.get("iss", "unknown")
    tool_claim = unverified.get("tool", "unknown")

    # ── Step 3: Resolve issuer DID → public key ──────────────
    try:
        public_key_pem = await get_public_key_pem(iss)
    except Exception as e:
        return _deny(401, f"Cannot resolve issuer DID: {iss}", "did_resolution", iss, tool_claim)

    # ── Step 4: Verify signature + exp + aud ─────────────────
    try:
        payload = verify_token(token, public_key_pem, expected_aud=SERVER_DID)
    except Exception as e:
        # Determine which check failed for structured reporting
        error_str = str(e).lower()
        if "expired" in error_str:
            stage = "token_expiry"
        elif "audience" in error_str:
            stage = "audience_validation"
        elif "signature" in error_str:
            stage = "signature_verification"
        else:
            stage = "jwt_verification"
        return _deny(401, f"JWT verification failed: {e}", stage, iss, tool_claim)

    # ── Step 5: Parse request body ───────────────────────────
    body = await request.json()
    requested_tool = body.get("tool")
    params = body.get("params", {}) or {}

    if not requested_tool:
        return _deny(400, "Missing tool in request body", "request_parse", iss)

    # ── Step 6: Tool binding (JWT claim must match request) ──
    if payload.get("tool") != requested_tool:
        return _deny(
            401,
            f"Tool mismatch: token claims '{payload.get('tool')}' but request asks '{requested_tool}'",
            "tool_binding",
            iss,
            requested_tool,
        )

    # ── Step 7: Replay protection (jti nonce) ────────────────
    jti = payload.get("jti")
    if not jti:
        return _deny(401, "Missing jti (nonce) in token", "replay_protection", iss, requested_tool)
    if seen_before(jti):
        return _deny(401, "Replay detected: jti has been used before", "replay_protection", iss, requested_tool)
    exp_at = payload.get("exp", 0)
    store_nonce(jti, exp_at)

    # ── Step 8: Rate limiting ────────────────────────────────
    agent_did = payload.get("iss", "")
    rate_ok, rate_reason = check_rate_limit(agent_did)
    if not rate_ok:
        return _deny(429, rate_reason, "rate_limit", agent_did, requested_tool)

    # ── Step 9: Policy enforcement ───────────────────────────
    ok, reason = is_allowed(agent_did, requested_tool, params)
    audit_log.policy_decision(agent_did, requested_tool, ok, reason)
    if not ok:
        return _deny(403, reason, "policy_enforcement", agent_did, requested_tool)

    # ── Step 10: Tool integrity (hash match) ─────────────────
    token_tool_hash = payload.get("tool_hash")
    if not token_tool_hash:
        return _deny(401, "Missing tool_hash claim in token", "tool_integrity", agent_did, requested_tool)

    try:
        expected_hash = await get_tool_hash(requested_tool)
    except KeyError:
        return _deny(403, f"Unknown/unregistered tool: {requested_tool}", "tool_integrity", agent_did, requested_tool)

    if token_tool_hash != expected_hash:
        return _deny(
            401,
            f"Tool hash mismatch: possible tool poisoning (expected {expected_hash[:16]}..., got {token_tool_hash[:16]}...)",
            "tool_integrity",
            agent_did,
            requested_tool,
        )

    check_elapsed = (time.perf_counter() - check_start) * 1000

    # ── All checks passed — log and forward ──────────────────
    audit_log.verification_passed(agent_did, requested_tool, jti, check_elapsed)

    t0 = time.perf_counter()
    result = await _forward_upstream(requested_tool, params, token)
    forward_elapsed = (time.perf_counter() - t0) * 1000

    from dzt_proxy.config import upstream_mode as get_mode
    audit_log.request_forwarded(agent_did, requested_tool, get_mode(), 200, forward_elapsed)

    return result
