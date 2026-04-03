# dzt_proxy/jwt_utils.py
"""
JWT signing and verification for the DZT Proxy.

Uses ES256K (secp256k1) as specified in the project report.
All MCP tool calls carry a JWT with claims:
  iss       — sender DID
  aud       — target MCP server DID
  tool      — tool being invoked
  tool_hash — SHA-256 of the tool's canonical spec
  jti       — unique nonce (replay protection)
  session   — session identifier (optional, for audit correlation)
  iat / exp — timestamps
"""

from __future__ import annotations

import jwt  # PyJWT
from datetime import datetime, timedelta, timezone
from typing import Optional

ALGORITHM = "ES256K"  # secp256k1 — matches project report


def sign_token(
    private_key_pem: str,
    iss: str,
    aud: str,
    tool: str,
    jti: str,
    ttl_seconds: int = 60,
    tool_hash: Optional[str] = None,
    session: Optional[str] = None,
) -> str:
    """Create a signed JWT for an MCP tool call."""
    now = datetime.now(timezone.utc)
    payload: dict = {
        "iss": iss,
        "aud": aud,
        "tool": tool,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    if tool_hash:
        payload["tool_hash"] = tool_hash
    if session:
        payload["session"] = session

    return jwt.encode(payload, private_key_pem, algorithm=ALGORITHM)


def verify_token(token: str, public_key_pem: str, expected_aud: str) -> dict:
    """
    Verify signature, expiry, audience, and required claims.
    Raises jwt.exceptions on any failure.
    """
    return jwt.decode(
        token,
        public_key_pem,
        algorithms=[ALGORITHM],
        audience=expected_aud,
        options={"require": ["exp", "iat", "iss", "aud", "jti", "tool"]},
    )


def get_unverified_claims(token: str) -> dict:
    """
    Read claims WITHOUT verifying signature.
    Used only to extract the issuer DID so we can look up the right public key.
    """
    return jwt.decode(token, options={"verify_signature": False})
