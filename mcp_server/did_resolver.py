# mcp_server/did_resolver.py
"""DID resolver for the MCP server (server-side JWT verification)."""

import json
from pathlib import Path

DID_DOCS = {
    "did:web:dzt.local:agent1": Path("did/docs/did_web_dzt_local_agent1.json"),
    "did:web:dzt.local:agent2": Path("did/docs/did_web_dzt_local_agent2.json"),
    "did:web:dzt.local:mcpserver": Path("did/docs/did_web_dzt_local_mcpserver.json"),
}


def resolve_did(did: str) -> dict:
    path = DID_DOCS.get(did)
    if not path or not path.exists():
        raise ValueError(f"Unknown DID: {did}")
    return json.loads(path.read_text())


def get_public_key_pem(did: str) -> str:
    doc = resolve_did(did)
    methods = doc.get("verificationMethod", [])
    if not methods:
        raise ValueError(f"No verificationMethod in DID doc for {did}")
    return methods[0]["publicKeyPem"]
