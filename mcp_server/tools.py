# mcp_server/tools.py
from pathlib import Path
import subprocess

TOOL_SPECS = {
    "echo": {
        "name": "echo",
        "description": "Echo back input text.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
        },
    },
    "read_file": {
        "name": "read_file",
        "description": "Read a file from disk (demo).",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    "run_cmd": {
        "name": "run_cmd",
        "description": "Run a shell command (demo only, dangerous).",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
}


def echo(message: str) -> dict:
    return {"ok": True, "tool": "echo", "result": message}


def read_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"ok": False, "error": "File not found"}
    return {"ok": True, "tool": "read_file", "result": p.read_text(errors="ignore")}


# For demo ONLY — used to show "RCE/tool misuse" before policy blocks it.
# WARNING: This executes arbitrary commands. Never expose without DZT proxy.
def run_cmd(cmd: str) -> dict:
    try:
        out = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        return {"ok": True, "tool": "run_cmd", "result": out[:2000]}
    except Exception as e:
        return {"ok": False, "tool": "run_cmd", "error": str(e)}
