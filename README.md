# DZT-Proxy-for-MCP
Dcentralized Zero Trust Proxy for MCP (Model Context Protocol)

## Quick Start
```bash
pip install -r requirements.txt
docker-compose up -d  # MCP mock + DID server
python app.py  # Dev proxy

## Architecture

````mermaid
sequenceDiagram
    participant A as MCP Agent
    participant P as DZT Proxy
    participant D as DID Resolver
    participant S as MCP Server
    
    A->>P: Tool Call + JWT
    P->>D: Fetch DID Pubkey
    D-->>P: Pubkey
    Note over P: Verify:<br/>✓ Signature<br/>✓ Audience<br/>✓ tool_hash<br/>✓ nonce/exp<br/>✓ Policy
    alt PASS
        P->>S: Forward Request
        S-->>P: Tool Response
        P-->>A: Response
    else FAIL
        P-->>A: 403 Forbidden
    end
