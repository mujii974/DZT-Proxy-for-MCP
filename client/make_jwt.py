#!/usr/bin/env python3
"""
Mint a JWT for manual testing.

Usage:
    PYTHONPATH=. python client/make_jwt.py
    PYTHONPATH=. python client/make_jwt.py --tool echo --ttl 120
"""

import argparse
import uuid

from dzt_proxy.jwt_utils import sign_token
from dzt_proxy.config import AGENT_PRIVATE_KEY_PEM, AGENT_DID, SERVER_DID


def main():
    parser = argparse.ArgumentParser(description="Mint a DZT JWT")
    parser.add_argument("--tool", default="get_me")
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args()

    token = sign_token(
        private_key_pem=AGENT_PRIVATE_KEY_PEM,
        iss=AGENT_DID,
        aud=SERVER_DID,  # Must match proxy's SERVER_DID
        tool=args.tool,
        jti=str(uuid.uuid4()),
        ttl_seconds=args.ttl,
    )

    print(token)


if __name__ == "__main__":
    main()
