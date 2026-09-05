"""Both servers, through a real MCP client, against scripted API responses:
401 / 403 / 429 handling, missing-key behaviour, and the key-leak guarantee."""
import json

import pytest

from mcp_driver import available_servers, call_tools, raw_jsonrpc, server_env
from replay_server import ScriptedServer

CANARY = "tc_live_LEAKCANARY_0123456789abcdef0123456789abcdef"
pytestmark = pytest.mark.parametrize("kind", available_servers())


async def test_401_maps_to_key_hint(kind, tmp_home):
    srv = ScriptedServer(401, {"error": "Unauthorized", "detail": "Authentication required"}).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=CANARY)
        [r, b] = await call_tools(kind, env, [{"name": "newest_threats", "args": {"limit": 2}}, {"name": "api_budget", "args": {}}])
        assert r["is_error"] and "401" in r["text"] and "THREATCLUSTER_API_KEY" in r["text"] and "threatcluster.io/api" in r["text"]
        assert CANARY not in r["text"]
        assert srv.seen_headers[0].get("X-API-Key") == CANARY  # the one place the key may go
        assert not b["is_error"] and b["structured"]["last_error"]["status"] == 401
        assert b["structured"]["session"]["api_calls"] == 1 and b["structured"]["session"]["credits_spent"] == 0
    finally:
        srv.stop()


async def test_429_retry_after(kind, tmp_home):
    srv = ScriptedServer(429, {"detail": {"error": "rate_limit_exceeded", "message": "Free keys are limited to 30 requests per minute.",
                                          "limit": 30, "retry_after": 23}}, {"Retry-After": "23"}).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=CANARY)
        [r] = await call_tools(kind, env, [{"name": "search_everything", "args": {"query": "lockbit"}}])
        assert r["is_error"] and "429 rate_limit_exceeded" in r["text"] and "Retry after 23 seconds" in r["text"]
    finally:
        srv.stop()


async def test_daily_budget_exhausted(kind, tmp_home):
    body = {"detail": {"error": "daily_budget_exceeded", "message": "Free keys get 100 credits a day (this request costs 5).",
                       "limit": 100, "used": 101, "request_cost": 5, "reset": 1788566400, "upgrade_url": "/pricing"}}
    srv = ScriptedServer(429, body, {"Retry-After": "1200", "X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "100",
                                     "X-RateLimit-Reset": "1788566400", "X-Request-Cost": "5"}).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=CANARY)
        [r, b] = await call_tools(kind, env, [{"name": "search_everything", "args": {"query": "lockbit"}}, {"name": "api_budget", "args": {}}])
        assert r["is_error"] and "daily_budget_exceeded" in r["text"] and "Retry after 1200 seconds" in r["text"] and "00:00 UTC" in r["text"]
        assert b["structured"]["daily_credits"]["remaining"] == 0 and b["structured"]["daily_credits"]["limit"] == 100
    finally:
        srv.stop()


async def test_403_scope(kind, tmp_home):
    body = {"detail": {"error": "insufficient_scope", "message": "This endpoint requires the 'darkweb:read' scope.",
                       "required_scope": "darkweb:read", "granted_scopes": ["threats:read"]}}
    srv = ScriptedServer(403, body).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=CANARY)
        [r] = await call_tools(kind, env, [{"name": "leak_site_victims", "args": {}}])
        assert r["is_error"] and "403 insufficient_scope" in r["text"] and "darkweb:read" in r["text"] and "pricing" in r["text"]
    finally:
        srv.stop()


async def test_no_key_means_no_request(kind, tmp_home):
    srv = ScriptedServer(200, {"threats": []}).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=None)
        [r, b] = await call_tools(kind, env, [{"name": "newest_threats", "args": {}}, {"name": "api_budget", "args": {}}])
        assert r["is_error"] and "THREATCLUSTER_API_KEY" in r["text"] and "tc auth login" in r["text"]
        assert srv.requests == []
        assert b["structured"]["key_configured"] is False and b["structured"]["key_source"] == "none"
    finally:
        srv.stop()


async def test_key_never_reaches_stdout_or_stderr(kind, tmp_home):
    """Every byte the server writes, under a 401 (the noisiest path), with the
    key also smuggled into arguments, must be free of the key."""
    srv = ScriptedServer(401, {"error": "Unauthorized", "detail": f"Authentication required; you sent {CANARY}"}).start()
    try:
        env = server_env(tmp_home, api_base=srv.api_base, api_key=CANARY)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                         "clientInfo": {"name": "leak-test", "version": "0"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "search_threats", "arguments": {"query": CANARY}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "search_threats", "arguments": {"query": "x", "bogus": CANARY}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "api_budget", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 6, "method": "prompts/get", "params": {"name": "threatcluster_analyst", "arguments": {"question": CANARY}}},
        ]
        out, err = await raw_jsonrpc(kind, env, msgs)
    finally:
        srv.stop()
    assert out, "server produced no output"
    assert CANARY.encode() not in out, "API key leaked to stdout (MCP transport)"
    assert CANARY.encode() not in err, "API key leaked to stderr"
    # The 401 body quoted the key: it must have been redacted, not dropped.
    assert b"[redacted]" in out
    # A key pasted into a prompt argument is the user's own text; it is echoed only in the prompt, never elsewhere.
    lines = [json.loads(l) for l in out.splitlines() if l.strip()]
    assert any(m.get("id") == 6 for m in lines)
