"""
Unit tests for dzt_proxy.jwt_utils

Tests the JWT signing/verification pipeline:
  - Round-trip: sign → verify → claims match
  - Expired token rejection
  - Wrong audience rejection
  - Missing required claims
  - Tampered signature rejection
  - Session claim propagation
"""

import time
import uuid
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from dzt_proxy.jwt_utils import sign_token, verify_token, get_unverified_claims, ALGORITHM


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def keypair():
    """Generate a fresh ES256K keypair for testing."""
    private_key = ec.generate_private_key(ec.SECP256K1())

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return priv_pem, pub_pem


@pytest.fixture(scope="module")
def other_keypair():
    """A different keypair (for signature mismatch tests)."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pub_pem


ISSUER = "did:web:dzt.local:test-agent"
AUDIENCE = "did:web:dzt.local:test-server"


# ── Round-trip tests ──────────────────────────────────────────

class TestSignVerifyRoundTrip:

    def test_basic_round_trip(self, keypair):
        priv, pub = keypair
        jti = str(uuid.uuid4())

        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=jti, ttl_seconds=60, tool_hash="abc123",
        )

        claims = verify_token(token, pub, expected_aud=AUDIENCE)

        assert claims["iss"] == ISSUER
        assert claims["aud"] == AUDIENCE
        assert claims["tool"] == "echo"
        assert claims["jti"] == jti
        assert claims["tool_hash"] == "abc123"
        assert "iat" in claims
        assert "exp" in claims

    def test_session_claim_propagated(self, keypair):
        priv, pub = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()), session="session-42",
        )
        claims = verify_token(token, pub, expected_aud=AUDIENCE)
        assert claims["session"] == "session-42"

    def test_no_tool_hash_when_omitted(self, keypair):
        priv, pub = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()),
        )
        claims = verify_token(token, pub, expected_aud=AUDIENCE)
        assert "tool_hash" not in claims


# ── Rejection tests ───────────────────────────────────────────

class TestRejection:

    def test_expired_token_rejected(self, keypair):
        priv, pub = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()), ttl_seconds=-10,
        )
        with pytest.raises(Exception, match=".*xpir.*"):
            verify_token(token, pub, expected_aud=AUDIENCE)

    def test_wrong_audience_rejected(self, keypair):
        priv, pub = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()),
        )
        with pytest.raises(Exception):
            verify_token(token, pub, expected_aud="did:web:dzt.local:wrong")

    def test_wrong_public_key_rejected(self, keypair, other_keypair):
        priv, _ = keypair
        wrong_pub = other_keypair

        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()),
        )
        with pytest.raises(Exception):
            verify_token(token, wrong_pub, expected_aud=AUDIENCE)

    def test_corrupted_token_rejected(self, keypair):
        priv, pub = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()),
        )
        corrupted = token[:-5] + "XXXXX"
        with pytest.raises(Exception):
            verify_token(corrupted, pub, expected_aud=AUDIENCE)


# ── Unverified claims ─────────────────────────────────────────

class TestUnverifiedClaims:

    def test_can_read_issuer_without_key(self, keypair):
        priv, _ = keypair
        token = sign_token(
            private_key_pem=priv, iss=ISSUER, aud=AUDIENCE,
            tool="echo", jti=str(uuid.uuid4()),
        )
        claims = get_unverified_claims(token)
        assert claims["iss"] == ISSUER
        assert claims["tool"] == "echo"

    def test_malformed_token_raises(self):
        with pytest.raises(Exception):
            get_unverified_claims("not.a.jwt")
