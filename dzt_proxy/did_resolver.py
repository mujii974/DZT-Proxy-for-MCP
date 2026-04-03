# dzt_proxy/did_resolver.py
"""
DID Resolver for did:web method.

Resolves Decentralized Identifiers to their DID Documents, which contain
the public keys needed for JWT signature verification.

For local demo DIDs (did:web:dzt.local:*), resolution uses local JSON files.
For real did:web identifiers, resolution fetches the DID document over HTTPS.
"""

import json
import logging
from pathlib import Path
from urllib.parse import unquote
from typing import Dict

import httpx

logger = logging.getLogger("dzt.did_resolver")

# ── Local DID document registry ──────────────────────────────

_DID_DOCS_DIR = Path("did/docs")

LOCAL_DID_DOCS: Dict[str, Path] = {
    "did:web:dzt.local:agent1": _DID_DOCS_DIR / "did_web_dzt_local_agent1.json",
    "did:web:dzt.local:agent2": _DID_DOCS_DIR / "did_web_dzt_local_agent2.json",
    "did:web:dzt.local:mcpserver": _DID_DOCS_DIR / "did_web_dzt_local_mcpserver.json",
}

_LOCAL_DOC_CACHE: Dict[str, dict] = {}
_PUBLIC_KEY_CACHE: Dict[str, str] = {}


def did_web_to_url(did: str) -> str:
    """
    Convert a did:web identifier to the HTTPS URL of its DID document.

    Examples:
        did:web:example.com:user  -> https://example.com/user/.well-known/did.json
        did:web:example.com       -> https://example.com/.well-known/did.json
    """
    if not did.startswith("did:web:"):
        raise ValueError(f"Unsupported DID method (expected did:web): {did}")

    method_specific = did[len("did:web:"):]
    parts = method_specific.split(":")
    domain = unquote(parts[0])
    path_parts = [unquote(p) for p in parts[1:]]

    if path_parts:
        return f"https://{domain}/" + "/".join(path_parts) + "/.well-known/did.json"
    return f"https://{domain}/.well-known/did.json"


def resolve_did_local(did: str) -> dict:
    """Resolve a DID from local JSON files (for demo/testing)."""
    cached = _LOCAL_DOC_CACHE.get(did)
    if cached is not None:
        return cached

    path = LOCAL_DID_DOCS.get(did)
    if not path or not path.exists():
        raise ValueError(f"Unknown local DID: {did}")
    doc = json.loads(path.read_text())
    _LOCAL_DOC_CACHE[did] = doc
    logger.debug("Resolved DID locally: %s", did)
    return doc


async def resolve_did_http(did: str) -> dict:
    """Resolve a DID by fetching its document over HTTPS."""
    url = did_web_to_url(did)
    logger.info("Resolving DID over HTTP: %s -> %s", did, url)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            r.raise_for_status()
            return r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValueError(f"Failed to resolve DID over HTTP: {did}") from exc


async def resolve_did(did: str) -> dict:
    """
    Resolve a DID to its DID Document.
    Prefers local files for known demo DIDs, falls back to HTTP resolution.
    """
    if did in LOCAL_DID_DOCS and LOCAL_DID_DOCS[did].exists():
        return resolve_did_local(did)
    return await resolve_did_http(did)


async def get_public_key_pem(did: str) -> str:
    """
    Extract the first public key PEM from a DID Document.
    This key is used to verify JWT signatures from the identified entity.
    """
    cached_key = _PUBLIC_KEY_CACHE.get(did)
    if cached_key is not None:
        return cached_key

    doc = await resolve_did(did)
    verification_methods = doc.get("verificationMethod", [])
    if not verification_methods:
        raise ValueError(f"No verificationMethod found in DID document for {did}")
    public_key = verification_methods[0]["publicKeyPem"]
    _PUBLIC_KEY_CACHE[did] = public_key
    return public_key
