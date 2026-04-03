# mcp_server/jwt_utils.py
"""JWT verification for the MCP server (server-side trust chain)."""

import jwt  # PyJWT

ALGO = "ES256K"


def verify_token(token: str, public_key_pem: str, expected_aud: str):
    return jwt.decode(
        token,
        public_key_pem,
        algorithms=[ALGO],
        audience=expected_aud,
        options={"require": ["exp", "iat", "iss", "aud", "jti", "tool"]},
    )


def get_unverified_claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})
