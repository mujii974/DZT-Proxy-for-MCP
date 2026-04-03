# dzt_proxy/audit.py
"""
Structured audit logging for the DZT Proxy.

Every security decision (allow, deny, error) is logged as a structured
JSON record for post-hoc analysis, compliance, and capstone evaluation.

Usage:
    from dzt_proxy.audit import audit_log
    audit_log.verification_passed(agent_did, tool, jti, latency_ms)
    audit_log.verification_failed(agent_did, tool, reason, details)
"""

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Structured JSON logger — writes one JSON object per line
_json_handler = logging.FileHandler(LOG_DIR / "audit.jsonl", encoding="utf-8")
_json_handler.setLevel(logging.DEBUG)

# Human-readable console logger
_console_handler = logging.StreamHandler()
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(
    logging.Formatter("[%(asctime)s] %(levelname)-5s  %(message)s", datefmt="%H:%M:%S")
)

logger = logging.getLogger("dzt.audit")
logger.setLevel(logging.DEBUG)
logger.addHandler(_json_handler)
logger.addHandler(_console_handler)


def _emit(event_type: str, **fields):
    """Write a structured audit record."""
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **fields,
    }
    # JSON line for machine parsing
    _json_handler.emit(
        logging.LogRecord(
            name="dzt.audit",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=json.dumps(record, default=str),
            args=(),
            exc_info=None,
        )
    )
    # Human-readable console summary
    summary = f"[{event_type}] " + " | ".join(f"{k}={v}" for k, v in fields.items())
    logger.info(summary)


class AuditLog:
    """High-level audit interface used by the proxy."""

    @staticmethod
    def request_received(method: str, path: str, agent_did: str = "unknown"):
        _emit("REQUEST_RECEIVED", method=method, path=path, agent_did=agent_did)

    @staticmethod
    def verification_passed(agent_did: str, tool: str, jti: str, checks_ms: float):
        _emit(
            "VERIFICATION_PASSED",
            agent_did=agent_did,
            tool=tool,
            jti=jti,
            checks_ms=round(checks_ms, 2),
        )

    @staticmethod
    def verification_failed(agent_did: str, tool: str, reason: str, stage: str, details: str = ""):
        _emit(
            "VERIFICATION_FAILED",
            agent_did=agent_did,
            tool=tool,
            reason=reason,
            stage=stage,
            details=details,
        )

    @staticmethod
    def request_forwarded(agent_did: str, tool: str, upstream: str, response_status: int, round_trip_ms: float):
        _emit(
            "REQUEST_FORWARDED",
            agent_did=agent_did,
            tool=tool,
            upstream=upstream,
            response_status=response_status,
            round_trip_ms=round(round_trip_ms, 2),
        )

    @staticmethod
    def policy_decision(agent_did: str, tool: str, allowed: bool, reason: str):
        _emit(
            "POLICY_DECISION",
            agent_did=agent_did,
            tool=tool,
            allowed=allowed,
            reason=reason,
        )

    @staticmethod
    def baseline_passthrough(tool: str, note: str = ""):
        _emit("BASELINE_PASSTHROUGH", tool=tool, note=note)


audit_log = AuditLog()
