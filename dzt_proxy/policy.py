# dzt_proxy/policy.py
"""
Policy Enforcement Engine for the DZT Proxy.

Implements a per-DID allowlist that controls which tools each agent
is permitted to invoke, and what parameter constraints apply.

This engine demonstrates the principle that identity alone is not enough:
even an authenticated agent must be *authorized* for each specific action.

Policy structure:
    AGENT_POLICIES[did] = {
        "allowed_tools": {"tool_a", "tool_b"},
        "param_rules": {
            "tool_a": callable(params) -> (bool, str)
        }
    }
"""

import logging
import os
from typing import Dict, Set, Callable, Tuple, Any

logger = logging.getLogger("dzt.policy")

# ── Parameter validation rules ───────────────────────────────

def _read_file_rule(params: dict) -> Tuple[bool, str]:
    """Only allow reading specific safe paths."""
    path = (params or {}).get("path", "")
    allowed_paths = {"/etc/passwd", "/etc/hostname", "/tmp/demo.txt"}
    if path in allowed_paths:
        return True, "OK"
    return False, f"read_file blocked: path '{path}' not in allowed set"


def _echo_rule(params: dict) -> Tuple[bool, str]:
    """Reject echo messages that look like prompt injection attempts."""
    message = (params or {}).get("message", "")
    # Simple heuristic: reject messages containing suspicious patterns
    suspicious = [
        "ignore previous",
        "ignore all instructions",
        "system prompt",
        "EXECUTE:",
        "run_cmd",
        "<script>",
    ]
    lower = message.lower()
    for pattern in suspicious:
        if pattern.lower() in lower:
            return False, f"echo blocked: suspicious content detected ('{pattern}')"
    return True, "OK"


# ── Agent policies ───────────────────────────────────────────

AGENT_POLICIES: Dict[str, Dict[str, Any]] = {
    # Agent1: primary agent — access to echo, read_file, and GitHub tools
    "did:web:dzt.local:agent1": {
        "allowed_tools": {"echo", "read_file", "get_me"},
        "param_rules": {
            "read_file": _read_file_rule,
            "echo": _echo_rule,
        },
    },
    # Agent2: restricted agent — only echo, no file access
    "did:web:dzt.local:agent2": {
        "allowed_tools": {"echo"},
        "param_rules": {
            "echo": _echo_rule,
        },
    },
}

# Tools that are ALWAYS blocked regardless of agent identity
GLOBAL_BLOCKLIST: Set[str] = {"run_cmd"}


def is_allowed(agent_did: str, tool: str, params: dict) -> Tuple[bool, str]:
    """
    Evaluate whether an agent is authorized to invoke a tool with given params.

    Returns:
        (allowed: bool, reason: str)
    """
    # ── Global blocklist (RCE prevention) ────────────────────
    if tool in GLOBAL_BLOCKLIST:
        logger.warning("BLOCKED by global blocklist: %s tried %s", agent_did, tool)
        return False, f"Tool globally blocked: {tool}"

    # ── Dynamic GitHub-mode tools ────────────────────────────
    mode = os.getenv("UPSTREAM_MODE", "github").lower()
    dynamic_tools: Set[str] = set()
    if mode == "github":
        dynamic_tools.add("get_me")

    # ── Look up agent policy ─────────────────────────────────
    policy = AGENT_POLICIES.get(agent_did)
    if policy is None:
        logger.warning("BLOCKED unknown agent: %s", agent_did)
        return False, f"Unknown agent DID: {agent_did}"

    allowed_tools = policy["allowed_tools"] | dynamic_tools

    if tool not in allowed_tools:
        logger.warning("BLOCKED tool not in allowlist: %s -> %s", agent_did, tool)
        return False, f"Tool not allowed for {agent_did}: {tool}"

    # ── Parameter-level rules ────────────────────────────────
    rule_fn = policy.get("param_rules", {}).get(tool)
    if rule_fn is not None:
        ok, reason = rule_fn(params)
        if not ok:
            logger.warning("BLOCKED by param rule: %s -> %s: %s", agent_did, tool, reason)
            return False, reason

    logger.debug("ALLOWED: %s -> %s", agent_did, tool)
    return True, "OK"
