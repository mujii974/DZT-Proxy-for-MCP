# dzt_proxy/sse.py
"""
SSE (Server-Sent Events) parser for GitHub Copilot MCP responses.

GitHub MCP returns responses in SSE format:
    event: message
    data: {...json...}

This module extracts the first JSON payload from the SSE stream.
"""

import json


def extract_first_sse_json(text: str) -> dict:
    """
    Parse SSE text and return the first valid JSON data payload.
    Raises ValueError if no valid data line is found.
    """
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[len("data:"):].strip()
            if not payload:
                continue
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No valid SSE 'data:' JSON line found in response ({len(text)} chars)")
