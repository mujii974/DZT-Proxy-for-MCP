# mcp_server/baseline.py
"""
Baseline MCP Server — NO security.

Used to demonstrate the "before DZT" state:
  - No authentication
  - No replay protection
  - No tool binding
  - No policy enforcement

Any request, including attacks, will succeed.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from mcp_server.tools import TOOL_SPECS, echo, read_file, run_cmd

app = FastAPI(title="MCP Server (Baseline — No Security)")


class ToolCall(BaseModel):
    tool: str
    params: dict = {}


@app.get("/tools")
def list_tools():
    return TOOL_SPECS


@app.post("/tools/call")
def call_tool(req: ToolCall):
    if req.tool == "echo":
        return echo(req.params.get("message", ""))
    if req.tool == "read_file":
        return read_file(req.params.get("path", ""))
    if req.tool == "run_cmd":
        return run_cmd(req.params.get("cmd", ""))
    return {"ok": False, "error": f"Unknown tool: {req.tool}"}
