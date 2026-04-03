"""
Unit tests for dzt_proxy.did_resolver

Tests DID resolution and key extraction:
  - did:web URL generation
  - Local DID resolution from JSON files
  - Public key extraction
  - Unknown DID rejection
  - W3C DID document compliance
"""

import json
import pytest
from pathlib import Path

from dzt_proxy.did_resolver import (
    did_web_to_url,
    resolve_did_local,
    get_public_key_pem,
    LOCAL_DID_DOCS,
)


class TestDidWebToUrl:

    def test_simple_domain(self):
        url = did_web_to_url("did:web:example.com")
        assert url == "https://example.com/.well-known/did.json"

    def test_domain_with_path(self):
        url = did_web_to_url("did:web:example.com:user")
        assert url == "https://example.com/user/.well-known/did.json"

    def test_domain_with_nested_path(self):
        url = did_web_to_url("did:web:example.com:org:team:agent")
        assert url == "https://example.com/org/team/agent/.well-known/did.json"

    def test_local_dzt_agent(self):
        url = did_web_to_url("did:web:dzt.local:agent1")
        assert url == "https://dzt.local/agent1/.well-known/did.json"

    def test_invalid_did_method(self):
        with pytest.raises(ValueError, match="Unsupported DID method"):
            did_web_to_url("did:key:z6Mkf5rGMoatrSj1f4QWp7rmFZvZIN")

    def test_missing_did_prefix(self):
        with pytest.raises(ValueError):
            did_web_to_url("not-a-did")


class TestLocalResolution:

    def test_resolve_agent1(self):
        doc = resolve_did_local("did:web:dzt.local:agent1")
        assert doc["id"] == "did:web:dzt.local:agent1"
        assert len(doc["verificationMethod"]) >= 1

    def test_resolve_mcpserver(self):
        doc = resolve_did_local("did:web:dzt.local:mcpserver")
        assert doc["id"] == "did:web:dzt.local:mcpserver"

    def test_unknown_did_raises(self):
        with pytest.raises(ValueError, match="Unknown local DID"):
            resolve_did_local("did:web:dzt.local:nonexistent")


class TestPublicKeyExtraction:

    @pytest.mark.asyncio
    async def test_agent1_public_key(self):
        pem = await get_public_key_pem("did:web:dzt.local:agent1")
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.strip().endswith("-----END PUBLIC KEY-----")

    @pytest.mark.asyncio
    async def test_mcpserver_public_key(self):
        pem = await get_public_key_pem("did:web:dzt.local:mcpserver")
        assert "BEGIN PUBLIC KEY" in pem

    @pytest.mark.asyncio
    async def test_unknown_did_raises(self):
        with pytest.raises(ValueError):
            await get_public_key_pem("did:web:dzt.local:nobody")


class TestW3CCompliance:
    """Verify DID documents follow W3C DID Core specification."""

    def test_agent1_has_context(self):
        doc = resolve_did_local("did:web:dzt.local:agent1")
        assert "@context" in doc
        contexts = doc["@context"]
        assert "https://www.w3.org/ns/did/v1" in contexts

    def test_mcpserver_has_context(self):
        doc = resolve_did_local("did:web:dzt.local:mcpserver")
        assert "@context" in doc

    def test_agent1_has_authentication(self):
        doc = resolve_did_local("did:web:dzt.local:agent1")
        assert "authentication" in doc
        assert len(doc["authentication"]) >= 1

    def test_agent1_has_assertion_method(self):
        doc = resolve_did_local("did:web:dzt.local:agent1")
        assert "assertionMethod" in doc

    def test_mcpserver_has_service_endpoint(self):
        doc = resolve_did_local("did:web:dzt.local:mcpserver")
        assert "service" in doc
        svc = doc["service"][0]
        assert svc["type"] == "MCPServer"
        assert "serviceEndpoint" in svc

    def test_verification_method_structure(self):
        doc = resolve_did_local("did:web:dzt.local:agent1")
        vm = doc["verificationMethod"][0]
        assert "id" in vm
        assert "type" in vm
        assert "controller" in vm
        assert "publicKeyPem" in vm
        assert vm["controller"] == doc["id"]
