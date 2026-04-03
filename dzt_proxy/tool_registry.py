# dzt_proxy/tool_registry.py
"""
Tool Registry for the DZT Proxy.

Maintains canonical tool specifications and computes SHA-256 hashes
for tool-poisoning detection. When the hash in a JWT doesn't match
the registry's hash, the request is blocked.

In local mode, specs come from the upstream local MCP server's /tools endpoint.
In GitHub mode, specs are fetched from the GitHub MCP tools/list RPC and
merged with locally-defined tool specs (for demo tools like echo, read_file).
"""

import json
import hashlib
import logging
import uuid
import time
from typing import Dict, Any

import httpx

from dzt_proxy.config import upstream_mode, GITHUB_MCP_URL, GITHUB_PAT, LOCAL_MCP_TOOLS_CALL_URL
from dzt_proxy.sse import extract_first_sse_json

logger = logging.getLogger("dzt.tool_registry")

# ── Local/demo tool specs ────────────────────────────────────
# These MUST match the specs served by mcp_server/tools.py exactly,
# or tool-hash validation will produce false positives in local mode.

LOCAL_TOOL_SPECS: Dict[str, Dict[str, Any]] = {
    "echo": {
        "name": "echo",
        "description": "Echo back input text.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    },
    "read_file": {
        "name": "read_file",
        "description": "Read a file from disk (demo).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "run_cmd": {
        "name": "run_cmd",
        "description": "Run a shell command (demo only, dangerous).",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    "get_me": {
        "name": "get_me",
        "description": "Fetch GitHub profile via Copilot MCP",
        "inputSchema": {"type": "object"},
    },
}

_cache_remote: Dict[str, Dict[str, Any]] | None = None
_cache_local: Dict[str, Dict[str, Any]] | None = None
_cache_local_at: float = 0.0
_LOCAL_CACHE_TTL_SEC = 30.0


def sha256_json(obj: Any) -> str:
    """Canonical JSON hash of a tool spec for integrity checking."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(s).hexdigest()


async def _rpc(method: str, params: dict) -> dict:
    """JSON-RPC call to GitHub Copilot MCP (returns SSE)."""
    if not GITHUB_PAT:
        raise RuntimeError("Missing GITHUB_PAT env var")

    headers = {
        "Authorization": f"Bearer {GITHUB_PAT}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": method,
        "params": params,
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(GITHUB_MCP_URL, headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        return extract_first_sse_json(r.text)


async def fetch_tool_specs() -> Dict[str, Dict[str, Any]]:
    """
    Return the authoritative tool spec dictionary.

    - local mode: fetch from local MCP server's GET /tools endpoint
    - github mode: fetch from GitHub MCP tools/list, merge with LOCAL_TOOL_SPECS
    """
    mode = upstream_mode()

    if mode == "local":
        global _cache_local, _cache_local_at
        now = time.monotonic()
        if _cache_local is not None and (now - _cache_local_at) < _LOCAL_CACHE_TTL_SEC:
            return _cache_local

        tools_url = LOCAL_MCP_TOOLS_CALL_URL.replace("/tools/call", "/tools")
        async with httpx.AsyncClient() as client:
            r = await client.get(tools_url, timeout=10)
            r.raise_for_status()
            specs = r.json()
            _cache_local = specs
            _cache_local_at = now
            logger.debug("Fetched %d tool specs from local server", len(specs))
            return specs

    # GitHub mode: merge local definitions + remote GitHub tools
    merged: Dict[str, Dict[str, Any]] = dict(LOCAL_TOOL_SPECS)

    if GITHUB_PAT:
        global _cache_remote
        if _cache_remote is None:
            try:
                resp = await _rpc("tools/list", {})
                tools = resp.get("result", {}).get("tools", []) or []
                _cache_remote = {t.get("name"): t for t in tools if t.get("name")}
                logger.info("Cached %d remote tool specs from GitHub MCP", len(_cache_remote))
            except Exception as e:
                logger.warning("Failed to fetch remote tool specs: %s", e)
                _cache_remote = {}

        merged.update(_cache_remote)

    return merged


async def get_tool_hash(tool_name: str) -> str:
    """
    Compute the canonical hash of a tool's specification.
    Used for tool-poisoning detection: JWT tool_hash must match this.
    """
    spec_map = await fetch_tool_specs()
    spec = spec_map.get(tool_name)
    if not spec:
        raise KeyError(f"Unknown tool spec: {tool_name}")
    return sha256_json(spec)


def invalidate_cache():
    """Clear the remote tool spec cache (called on startup)."""
    global _cache_remote, _cache_local, _cache_local_at
    _cache_remote = None
    _cache_local = None
    _cache_local_at = 0.0
    logger.debug("Remote tool spec cache invalidated")
