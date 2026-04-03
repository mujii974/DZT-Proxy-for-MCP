# dzt_proxy/config.py
"""
Centralized configuration for the DZT Proxy.

All ports, URLs, and identity settings are controlled here.
Override any value via environment variables.
"""

import os
from pathlib import Path

# ── DID identities ───────────────────────────────────────────
AGENT_DID = os.getenv("AGENT_DID", "did:web:dzt.local:agent1")
SERVER_DID = os.getenv("SERVER_DID", "did:web:dzt.local:mcpserver")

# ── Proxy port (the DZT proxy itself) ────────────────────────
PROXY_PORT = int(os.getenv("PROXY_PORT", "8000"))

# ── Agent private key (used by client/eval scripts to mint JWTs) ──
_key_path = os.getenv("AGENT_PRIVATE_KEY_PATH", "did/keys/agent1_private.pem")
_key_file = Path(_key_path)
if _key_file.exists():
    AGENT_PRIVATE_KEY_PEM = _key_file.read_text()
else:
    # Fallback: try legacy location
    _alt = Path("agent1_private.pem")
    AGENT_PRIVATE_KEY_PEM = _alt.read_text() if _alt.exists() else ""

# ── Upstream mode ────────────────────────────────────────────
# "github" → forwards to GitHub Copilot MCP (JSON-RPC SSE)
# "local"  → forwards to the local mcp_server (plain JSON /tools/call)
UPSTREAM_MODE = os.getenv("UPSTREAM_MODE", "github").lower()


def upstream_mode() -> str:
    mode = os.getenv("UPSTREAM_MODE", UPSTREAM_MODE).lower()
    return mode if mode in ("github", "local") else "github"


# ── Upstream endpoints ───────────────────────────────────────
GITHUB_MCP_URL = os.getenv("GITHUB_MCP_URL", "https://api.githubcopilot.com/mcp/")
LOCAL_MCP_TOOLS_CALL_URL = os.getenv("UPSTREAM_URL", "http://127.0.0.1:8001/tools/call")

# ── GitHub PAT ───────────────────────────────────────────────
GITHUB_PAT = os.getenv("GITHUB_PAT", "")
