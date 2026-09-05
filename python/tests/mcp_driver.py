"""Drive either server (python or node) through a real MCP client over stdio,
plus a raw newline-delimited JSON-RPC driver that captures every byte of
stdout and stderr (for the key-leak test)."""
from __future__ import annotations

import asyncio
import copy
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
NODE_ENTRY = ROOT / "node" / "dist" / "index.js"

_DEVNULL = open(os.devnull, "w")
SERVERS: dict[str, list[str]] = {
    "python": [sys.executable, "-m", "threatcluster_mcp"],
    "node": ["node", str(NODE_ENTRY)],
}


def available_servers() -> list[str]:
    out = ["python"]
    if NODE_ENTRY.exists():
        out.append("node")
    return out


def server_env(tmp_home: Path, *, api_base: str, api_key: Optional[str], site: str = "https://threatcluster.io") -> dict[str, str]:
    """A minimal, deterministic environment: no inherited THREATCLUSTER_* / TC_*
    variables, an empty XDG_CONFIG_HOME so no tc-cli file is picked up."""
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "PYTHONPATH", "NODE_PATH", "TMPDIR")}
    env["HOME"] = str(tmp_home)
    env["XDG_CONFIG_HOME"] = str(tmp_home / "xdg")
    # HOME is redirected, so point the interpreter's user site-packages back at
    # the real one (that is where `pip install --user` put mcp/httpx).
    import site as _site
    env["PYTHONUSERBASE"] = _site.getuserbase()
    env["THREATCLUSTER_API_BASE"] = api_base
    env["THREATCLUSTER_SITE"] = site
    if api_key:
        env["THREATCLUSTER_API_KEY"] = api_key
    return env


async def with_session(kind: str, env: dict[str, str], fn):
    cmd = SERVERS[kind]
    params = StdioServerParameters(command=cmd[0], args=cmd[1:], env=env)
    async with stdio_client(params, errlog=_DEVNULL) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            return await fn(s, init)


async def list_tools(kind: str, env: dict[str, str]) -> list[dict]:
    async def _fn(s, init):
        res = await s.list_tools()
        return [t.model_dump(exclude_none=True) for t in res.tools]
    return await with_session(kind, env, _fn)


async def call_tools(kind: str, env: dict[str, str], calls: list[dict]) -> list[dict]:
    """Run ``calls`` ([{name, args}]) in ONE session, in order. Each result is
    {"is_error", "text", "structured"}; structured is parsed from the text
    content so both servers are judged on the same channel."""
    async def _fn(s, init):
        out = []
        for c in calls:
            res = await s.call_tool(c["name"], c.get("args") or {})
            text = "".join(getattr(b, "text", "") for b in res.content)
            structured = None
            if not res.isError:
                try:
                    structured = json.loads(text)
                except ValueError:
                    structured = None
            out.append({"is_error": bool(res.isError), "text": text, "structured": structured,
                        "structured_content": res.structuredContent})
        return out
    return await with_session(kind, env, _fn)


VOLATILE_TOP = {"as_of"}


def stable(result: Any) -> Any:
    """Drop the fields that legitimately differ between runs / servers."""
    r = copy.deepcopy(result)
    if not isinstance(r, dict):
        return r
    for k in VOLATILE_TOP:
        r.pop(k, None)
    if r.get("tool") == "api_budget":
        r.pop("api_base", None)  # the replay server's port
        r.get("session", {}).pop("started_at", None)
        r.get("session", {}).pop("requests_last_minute", None)
        r.get("last_response", {}).pop("at", None)
    return r


async def raw_jsonrpc(kind: str, env: dict[str, str], requests: list[dict], timeout: float = 60.0) -> tuple[bytes, bytes]:
    """Send newline-delimited JSON-RPC to the server and return ALL bytes it
    wrote to stdout and stderr. ``requests`` are sent in order; responses are
    awaited for each request that carries an id."""
    cmd = SERVERS[kind]
    proc = await asyncio.create_subprocess_exec(*cmd, env=env, stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    assert proc.stdin and proc.stdout and proc.stderr
    out_chunks: list[bytes] = []

    async def read_response(want_id):
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout)
            if not line:
                return None
            out_chunks.append(line)
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get("id") == want_id:
                return msg

    for req in requests:
        proc.stdin.write((json.dumps(req) + "\n").encode())
        await proc.stdin.drain()
        if "id" in req:
            await read_response(req["id"])
    proc.stdin.close()
    try:
        rest, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        rest, err = await proc.communicate()
    return b"".join(out_chunks) + rest, err
