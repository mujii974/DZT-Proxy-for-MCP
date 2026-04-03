#!/usr/bin/env python3
"""
DZT Client — Make authenticated tool calls through the DZT Proxy.

Usage:
    python client/call_tool.py --tool echo --params '{"message": "hello"}'
    python client/call_tool.py --tool get_me
    python client/call_tool.py --tool read_file --params '{"path": "/etc/passwd"}'
"""

import uuid
import json
import argparse
import asyncio
import requests

from dzt_proxy.tool_registry import get_tool_hash
from dzt_proxy.jwt_utils import sign_token
from dzt_proxy.config import AGENT_PRIVATE_KEY_PEM, AGENT_DID, SERVER_DID

PROXY_URL = "http://127.0.0.1:8000"


def call_tool(tool: str, params: dict):
    """Make an authenticated tool call through the DZT proxy."""
    # 1) Get the canonical tool hash
    tool_hash = asyncio.run(get_tool_hash(tool))

    # 2) Mint a signed JWT
    jti = str(uuid.uuid4())
    token = sign_token(
        private_key_pem=AGENT_PRIVATE_KEY_PEM,
        iss=AGENT_DID,
        aud=SERVER_DID,
        tool=tool,
        jti=jti,
        ttl_seconds=60,
        tool_hash=tool_hash,
    )

    # 3) Send the request
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"tool": tool, "params": params}
    r = requests.post(f"{PROXY_URL}/tools/call", json=payload, headers=headers, timeout=30)

    # 4) Display results
    print(f"Status: {r.status_code}")
    try:
        body = r.json()
        print(f"Response: {json.dumps(body, indent=2)}")
    except Exception:
        print(f"Response: {r.text[:500]}")


def main():
    parser = argparse.ArgumentParser(description="DZT Client")
    parser.add_argument("--tool", required=True, help="Tool name (echo, read_file, get_me)")
    parser.add_argument("--params", default="{}", help='JSON params, e.g. \'{"message":"hi"}\'')
    args = parser.parse_args()

    params = json.loads(args.params)
    call_tool(args.tool, params)


if __name__ == "__main__":
    main()
