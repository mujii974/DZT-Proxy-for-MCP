# Decentralized Zero-Trust (DZT) Proxy for MCP

A security proxy that enforces continuous cryptographic verification on every
MCP (Model Context Protocol) tool call using **decentralized identity (DIDs)**,
**per-message JWT signing**, and **real-time policy enforcement**.

---

## Architecture

```
┌──────────┐     JWT + Request     ┌───────────┐     Verified Request    ┌────────────┐
│ MCP      │ ──────────────────►  │ DZT Proxy │ ──────────────────────► │ MCP Server │
│ Client   │                      │ (FastAPI)  │                        │ (GitHub/   │
│ (Agent)  │ ◄──────────────────  │           │ ◄────────────────────── │  Local)    │
└──────────┘     Response          └───────────┘     Response            └────────────┘
                                        │
                                  8-Step Verification:
                                  ├─ 1. Token Presence
                                  ├─ 2. DID Resolution
                                  ├─ 3. Signature + Expiry + Audience
                                  ├─ 4. Tool Binding
                                  ├─ 5. Replay Protection (jti)
                                  ├─ 6. Rate Limiting
                                  ├─ 7. Policy Enforcement
                                  └─ 8. Tool Hash Integrity
```

## Proposed Design Evolution

The implementation intentionally evolved from the initial proposal:

- **Flask -> FastAPI**: the proxy moved to FastAPI for better async request handling,
  clearer request/response modeling, and straightforward health/debug endpoints used
  by the evaluation tooling.
- **python-jose -> PyJWT**: JWT handling was standardized on PyJWT to simplify signing
  and verification flows used throughout the DZT pipeline and attack simulations.

This is a design evolution decision, not a scope change: the zero-trust goals remain
the same while the implementation stack was adjusted for reliability and maintainability.

## Quick Start

```bash
# 1. Clone and setup
git clone <repository-url>
cd capstone-dzt-proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
nano .env   # Add your GITHUB_PAT (needed for options 3 & 4)

# 3. Run
bash run_menu.sh
```

## Docker Quick Start

Run the local secured stack (baseline MCP server + DZT proxy):

```bash
cp .env.example .env
docker compose up --build -d
```

Endpoints:

- Proxy: `http://127.0.0.1:8000/health`
- Local MCP (baseline): `http://127.0.0.1:8001/tools`

Run proxy against GitHub MCP (without local upstream):

```bash
cp .env.example .env
# Set GITHUB_PAT in .env first
UPSTREAM_MODE=github docker compose up --build -d dzt_proxy
```

Stop containers:

```bash
docker compose down
```

## Menu Options

```
  1)  Local MCP — WITHOUT Proxy  (no security)
  2)  Local MCP — WITH Proxy     (DZT secured)
  3)  GitHub MCP — WITHOUT Proxy (direct, PAT only)
  4)  GitHub MCP — WITH Proxy    (DZT secured)
  5)  Exit
```

- **Option 1** starts a local MCP server with zero security, runs attacks directly. All attacks succeed.
- **Option 2** starts the same server behind the DZT Proxy. Attacks are blocked.
- **Option 3** sends attacks directly to the real GitHub MCP API using your PAT. No local servers needed.
- **Option 4** puts the DZT Proxy in front of GitHub MCP. Proxy blocks attacks before they reach GitHub.

Every result shows the **real HTTP response** — status code, BLOCKED/ALLOWED, which defense caught it, and latency.

Servers start and stop automatically. All secrets loaded from `.env`.

## Unit Tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

## Project Structure

```
capstone-dzt-proxy/
├── dzt_proxy/                # Core proxy implementation
│   ├── app.py                # FastAPI proxy (8-step verification pipeline)
│   ├── audit.py              # Structured JSON audit logging
│   ├── config.py             # Centralized configuration
│   ├── did_resolver.py       # DID resolution (local + HTTP)
│   ├── jwt_utils.py          # JWT signing/verification (ES256K)
│   ├── nonce_store.py        # Replay protection (SQLite + TTL cleanup)
│   ├── policy.py             # Per-DID tool allowlist + param rules
│   ├── rate_limiter.py       # Per-DID sliding window rate limiting
│   ├── sse.py                # SSE parser for GitHub MCP responses
│   └── tool_registry.py      # Tool spec hashing (SHA-256 integrity)
│
├── mcp_server/               # Local MCP server
│   ├── baseline.py           # No-security server (menu option 1)
│   ├── server.py             # Secured server (defense-in-depth)
│   └── tools.py              # Tool implementations (echo, read_file, run_cmd)
│
├── eval/
│   ├── attack_runner.py      # Unified attack engine (all 4 modes)
│   └── results/              # JSON output from runs
│
├── tests/                    # Unit tests (pytest)
│   ├── test_core.py          # Integration tests
│   ├── test_jwt_utils.py
│   ├── test_policy.py
│   ├── test_nonce_store.py
│   ├── test_did_resolver.py
│   ├── test_tool_registry.py
│   └── test_rate_limiter.py
│
├── did/
│   ├── docs/                 # W3C-compliant DID documents
│   └── keys/                 # ES256K keypairs
│
├── client/
│   ├── call_tool.py          # CLI tool for authenticated proxy calls
│   └── make_jwt.py           # JWT minting utility
│
├── scripts/
│   └── setup_agent2.py       # Generate agent2 identity (multi-agent demo)
│
├── run_menu.sh               # Interactive 5-option attack menu
├── Dockerfile                # Container image for proxy/server runtime
├── docker-compose.yml        # Local container orchestration
├── .dockerignore
├── .env.example              # Configuration template
├── requirements.txt
└── pytest.ini
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_PAT` | GitHub Personal Access Token (options 3 & 4) |
| `AGENT_DID` | Agent identity (default: `did:web:dzt.local:agent1`) |
| `SERVER_DID` | Server identity (default: `did:web:dzt.local:mcpserver`) |
| `AGENT_PRIVATE_KEY_PATH` | Path to agent's ES256K private key |
