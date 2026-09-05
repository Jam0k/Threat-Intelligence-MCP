"""stdio MCP server exposing the ThreatCluster public API.

Run as ``threatcluster-mcp`` (console script), ``python -m threatcluster_mcp``
or ``uvx threatcluster-mcp``. The server name is ``threatcluster``; tools and
prompts come verbatim from ``tools.json``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from . import __version__
from .client import (ApiError, ENV_API_BASE, ENV_API_KEY, FREE_KEY_URL, ThreatClusterClient, resolve_api_key,
                     scrub_key_shapes)
from .tools import ToolInputError, ToolRunner, load_spec, prompt_specs, render_prompt, tool_spec, tool_specs, validate_args

log = logging.getLogger("threatcluster_mcp")

ANNOTATIONS = types.ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)


def _error_result(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=True)


def build_server(client: ThreatClusterClient) -> Server:
    spec = load_spec()
    runner = ToolRunner(client)
    server: Server = Server(spec["server"]["name"], version=__version__, instructions=spec["server"]["instructions"])

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        return [types.Tool(name=t["name"], title=t.get("title"), description=t["description"], inputSchema=t["inputSchema"],
                           annotations=ANNOTATIONS) for t in tool_specs()]

    # validate_input=False: we validate against the same schema ourselves so
    # the error text is identical to the npm package's.
    @server.call_tool(validate_input=False)
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> types.CallToolResult:
        t = tool_spec(name)
        if t is None:
            return _error_result(f"unknown tool '{name}'")
        try:
            args = validate_args(t["inputSchema"], arguments)
        except ToolInputError as e:
            return _error_result(f"invalid arguments for {name}: {client.redact(scrub_key_shapes(str(e)))}")
        if name != "api_budget" and not client.has_key:
            return _error_result(f"No ThreatCluster API key is configured. Set {ENV_API_KEY} (free key: {FREE_KEY_URL}) "
                                 "or run `tc auth login` with the ThreatCluster CLI.")
        try:
            result = await runner.run(name, args)
        except ApiError as e:
            return _error_result(client.redact(e.to_text()))
        except ToolInputError as e:
            return _error_result(f"invalid arguments for {name}: {client.redact(str(e))}")
        except Exception as e:  # never let a traceback (which could quote a request) reach the client
            log.warning("tool %s failed: %s", name, client.redact(f"{type(e).__name__}: {e}"))
            return _error_result(f"{name} failed: {client.redact(scrub_key_shapes(f'{type(e).__name__}: {e}'))}")
        text = json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str)
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)], structuredContent=result)

    @server.list_prompts()
    async def _list_prompts() -> list[types.Prompt]:
        return [types.Prompt(name=p["name"], title=p.get("title"), description=p["description"],
                             arguments=[types.PromptArgument(name=a["name"], description=a.get("description"),
                                                             required=bool(a.get("required"))) for a in p.get("arguments", [])])
                for p in prompt_specs()]

    @server.get_prompt()
    async def _get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        for p in prompt_specs():
            if p["name"] == name:
                return types.GetPromptResult(description=p["description"], messages=[
                    types.PromptMessage(role="user", content=types.TextContent(
                        type="text", text=client.redact(render_prompt(p, arguments))))])
        raise ValueError(f"unknown prompt '{name}'")

    return server


async def serve() -> None:
    key, source = resolve_api_key()
    client = ThreatClusterClient(key, key_source=source)
    if not key:
        log.warning("no API key found (%s unset, no tc-cli credential); tools will return an auth error. Free key: %s",
                    ENV_API_KEY, FREE_KEY_URL)
    server = build_server(client)
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options(), raise_exceptions=False)
    finally:
        await client.aclose()


def _check() -> int:
    key, source = resolve_api_key()
    client = ThreatClusterClient(key, key_source=source)
    # Never print the key. Only where it came from and where it will be sent.
    sys.stderr.write(f"threatcluster-mcp {__version__}\n")
    sys.stderr.write(f"api base: {client.base}  ({ENV_API_BASE})\n")
    sys.stderr.write(f"api key : {'configured' if key else 'MISSING'} (source: {source})\n")
    sys.stderr.write(f"tools   : {', '.join(t['name'] for t in tool_specs())}\n")
    if not key:
        sys.stderr.write(f"set {ENV_API_KEY}; free keys at {FREE_KEY_URL}\n")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="%(name)s: %(message)s")
    # httpx/httpcore never get to log request lines (which carry query strings) at a level we ship.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if "--version" in argv or "-V" in argv:
        sys.stdout.write(f"threatcluster-mcp {__version__}\n")
        return 0
    if "--check" in argv:
        return _check()
    if "--help" in argv or "-h" in argv:
        sys.stdout.write("usage: threatcluster-mcp [--check] [--version]\n"
                         "MCP server (stdio) for the ThreatCluster API. Configure THREATCLUSTER_API_KEY.\n")
        return 0
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
