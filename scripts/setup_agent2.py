#!/usr/bin/env python3
"""
Generate ES256K keys and DID document for agent2.

This demonstrates the decentralized identity model:
  - agent1: full access (echo, read_file, get_me)
  - agent2: restricted access (echo only)

Usage:
    python scripts/setup_agent2.py
"""

import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = ROOT / "did" / "keys"
DOC_DIR = ROOT / "did" / "docs"


def main():
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    DOC_DIR.mkdir(parents=True, exist_ok=True)

    # Generate secp256k1 keypair (ES256K)
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

    # Write key files
    (KEY_DIR / "agent2_private.pem").write_text(priv_pem)
    (KEY_DIR / "agent2_public.pem").write_text(pub_pem)

    # Build W3C-compliant DID document
    did_doc = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1",
        ],
        "id": "did:web:dzt.local:agent2",
        "verificationMethod": [
            {
                "id": "did:web:dzt.local:agent2#key-1",
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": "did:web:dzt.local:agent2",
                "publicKeyPem": pub_pem,
            }
        ],
        "authentication": ["did:web:dzt.local:agent2#key-1"],
        "assertionMethod": ["did:web:dzt.local:agent2#key-1"],
    }

    doc_path = DOC_DIR / "did_web_dzt_local_agent2.json"
    doc_path.write_text(json.dumps(did_doc, indent=2) + "\n")

    print("Agent2 identity created successfully:")
    print(f"  Private key : did/keys/agent2_private.pem")
    print(f"  Public key  : did/keys/agent2_public.pem")
    print(f"  DID document: did/docs/did_web_dzt_local_agent2.json")
    print(f"  DID         : did:web:dzt.local:agent2")
    print()
    print("Policy permissions (from dzt_proxy/policy.py):")
    print("  agent2 can only use: echo")
    print("  agent2 CANNOT use:   read_file, get_me, run_cmd")
    print()
    print("Test with:")
    print("  AGENT_DID=did:web:dzt.local:agent2 \\")
    print("  AGENT_PRIVATE_KEY_PATH=did/keys/agent2_private.pem \\")
    print("  python eval/test_multi_agent.py")


if __name__ == "__main__":
    main()
