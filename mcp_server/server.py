# mcp_server/server.py
"""
Secured MCP Server (with server-side JWT verification).

This is the "complete trust chain" server: even if the proxy is bypassed,
this server independently verifies every JWT before executing a tool.
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from mcp_server.tools import TOOL_SPECS, echo, read_file, run_cmd
from mcp_server.did_resolver import get_public_key_pem
from mcp_server.jwt_utils import verify_token, get_unverified_claims
from mcp_server.nonce_store import init_db, seen_before, store_nonce

SERVER_DID = "did:web:dzt.local:mcpserver"

app = FastAPI(title="MCP Server (Secured)")


@app.on_event("startup")
def _startup():
    init_db()


class ToolCall(BaseModel):
    tool: str
    params: dict = {}


@app.get("/tools")
def list_tools():
    return TOOL_SPECS


@app.post("/tools/call")
async def call_tool(req: ToolCall, request: Request):
    # 1) Require Bearer token
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token (server-side)")
    token = auth.split(" ", 1)[1].strip()

    # 2) Decode issuer DID (unverified)
    try:
        unverified = get_unverified_claims(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed JWT (server-side)")

    iss = unverified.get("iss")
    if not iss:
        raise HTTPException(status_code=401, detail="Missing iss claim (server-side)")

    # 3) Resolve DID → public key
    try:
        pubkey = get_public_key_pem(iss)
    except Exception:
        raise HTTPException(status_code=401, detail=f"Unknown issuer DID: {iss} (server-side)")

    # 4) Verify signature + aud + exp
    try:
        payload = verify_token(token, pubkey, expected_aud=SERVER_DID)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"JWT verification failed (server-side): {e}")

    # 5) Tool binding
    if payload.get("tool") != req.tool:
        raise HTTPException(status_code=401, detail="Tool mismatch (server-side)")

    # 6) Replay protection
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=401, detail="Missing jti (server-side)")
    if seen_before(jti):
        raise HTTPException(status_code=401, detail="Replay detected (server-side)")
    store_nonce(jti, payload.get("exp", 0))

    # 7) Execute tool
    if req.tool == "echo":
        return echo(req.params.get("message", ""))
    if req.tool == "read_file":
        return read_file(req.params.get("path", ""))
    if req.tool == "run_cmd":
        return run_cmd(req.params.get("cmd", ""))
    return {"ok": False, "error": f"Unknown tool: {req.tool}"}
