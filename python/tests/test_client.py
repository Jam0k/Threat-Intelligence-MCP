"""Unit tests for the HTTP client: header parsing, error mapping, redaction and
credential resolution. No network: httpx.MockTransport."""
import json
import os
import stat

import httpx
import pytest

from threatcluster_mcp import client as C
from threatcluster_mcp.client import ApiError, ThreatClusterClient, resolve_api_key, scrub_key_shapes

KEY = "tc_live_unitTESTkey_0123456789abcdef0123456789"


def make(handler, key=KEY):
    return ThreatClusterClient(key, base="https://api.test/api/public/v1", site="https://site.test", key_source="env",
                               transport=httpx.MockTransport(handler))


async def test_auth_header_api_key_and_bearer():
    seen = {}

    def h(req):
        seen.update(dict(req.headers))
        return httpx.Response(200, json={"ok": True}, headers={"X-Request-Cost": "1"})

    body, cost = await make(h).get("/threats", {"limit": 3, "keyword": None, "x": ""})
    assert body == {"ok": True} and cost == 1
    assert seen["x-api-key"] == KEY and "authorization" not in seen
    assert seen["accept"] == "application/json" and seen["user-agent"].startswith("threatcluster-mcp/")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
    seen.clear()
    await make(h, key=jwt).get("/threats")
    assert seen["authorization"] == "Bearer " + jwt and "x-api-key" not in seen


async def test_none_params_dropped_and_budget_parsed():
    urls = []

    def h(req):
        urls.append(str(req.url))
        return httpx.Response(200, json={}, headers={"X-Request-Cost": "5", "X-RateLimit-Limit": "100",
                                                     "X-RateLimit-Remaining": "80", "X-RateLimit-Reset": "1788566400"})

    c = make(h)
    await c.get("/search", {"q": "lockbit", "days": None, "limit": 3})
    assert urls == ["https://api.test/api/public/v1/search?q=lockbit&limit=3"]
    b = c.budget
    assert (b.limit, b.remaining, b.reset_epoch, b.session_cost, b.session_calls) == (100, 80, 1788566400, 5, 1)
    assert b.brief() == {"remaining": 80, "limit": 100, "resets_at": "2026-09-05T00:00:00Z"}
    snap = b.snapshot()
    assert snap["session"]["credits_spent"] == 5 and snap["last_response"]["status"] == 200 and snap["last_error"] is None


@pytest.mark.parametrize("status,body,headers,code,frag,retry", [
    (401, {"error": "Unauthorized", "detail": "Authentication required"}, {}, "Unauthorized", "THREATCLUSTER_API_KEY", None),
    (403, {"detail": {"error": "insufficient_scope", "message": "This endpoint requires the 'mssp:read' scope.",
                      "required_scope": "mssp:read", "granted_scopes": ["threats:read"]}}, {}, "insufficient_scope", "mssp:read", None),
    (403, {"detail": {"error": "lookback_exceeded", "message": "older than the 7-day window", "lookback_days": 7}}, {},
     "lookback_exceeded", "last 7 days", None),
    (404, {"error": "Endpoint not found", "path": "/x"}, {}, "not_found", "nothing matches /threats/zzz", None),
    (429, {"detail": {"error": "rate_limit_exceeded", "message": "Free keys are limited to 30 requests per minute.",
                      "retry_after": 17}}, {"Retry-After": "17"}, "rate_limit_exceeded", "Retry after 17 seconds", 17),
    (429, {"detail": {"error": "daily_budget_exceeded", "message": "Free keys get 100 credits a day"}},
     {"Retry-After": "3600"}, "daily_budget_exceeded", "00:00 UTC", 3600),
    (429, "slow down", {}, "rate_limited", "Retry after 60 seconds", 60),
    (500, "boom", {}, "server_error", "retry once", None),
])
async def test_error_mapping(status, body, headers, code, frag, retry):
    def h(req):
        return httpx.Response(status, json=body, headers=headers) if not isinstance(body, str) else httpx.Response(status, text=body, headers=headers)

    c = make(h)
    with pytest.raises(ApiError) as e:
        await c.get("/threats/zzz")
    err = e.value
    assert err.status == status and err.code == code and err.retry_after == retry
    assert frag in err.to_text()
    assert c.budget.last_error == err.to_dict()
    assert KEY not in err.to_text()


async def test_network_and_bad_json_errors():
    def boom(req):
        raise httpx.ConnectError(f"refused for {KEY}")  # a message that quotes the key must be scrubbed

    with pytest.raises(ApiError) as e:
        await make(boom).get("/threats")
    assert e.value.code == "network_error" and KEY not in e.value.to_text() and "[redacted]" in e.value.to_text()

    def html(req):
        return httpx.Response(200, text="<html>gateway</html>")

    with pytest.raises(ApiError) as e:
        await make(html).get("/threats")
    assert e.value.code == "bad_response"

    def slow(req):
        raise httpx.ReadTimeout("t")

    with pytest.raises(ApiError) as e:
        await make(slow).get("/threats")
    assert e.value.code == "timeout"


def test_redact_and_scrub():
    c = ThreatClusterClient(KEY, key_source="env")
    assert c.redact(f"header X-API-Key: {KEY} sent") == "header X-API-Key: [redacted] sent"
    assert c.redact(None) == ""
    assert ThreatClusterClient("short", key_source="env").redact("short key stays") == "short key stays"  # < 8 chars: not a real key
    assert scrub_key_shapes("k=tc_agent_abcdefghijklmnop rest") == "k=tc_[redacted] rest"


def test_resolve_key_precedence(monkeypatch, tmp_path):
    monkeypatch.delenv("THREATCLUSTER_API_KEY", raising=False)
    monkeypatch.delenv("TC_REFRESH_TOKEN", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setitem(__import__("sys").modules, "tc_cli", None)  # simulate tc-cli not installed
    assert resolve_api_key() == (None, "none")
    d = tmp_path / "tc-cli"
    d.mkdir()
    f = d / "credentials"
    f.write_text("tc_live_fromfile_000000000000\n")
    os.chmod(f, 0o644)
    assert resolve_api_key() == (None, "none")  # insecure mode is ignored
    os.chmod(f, 0o600)
    assert resolve_api_key() == ("tc_live_fromfile_000000000000", "tc-cli-file")
    monkeypatch.setenv("TC_REFRESH_TOKEN", "tc_agent_fromtcenv_00000000000")
    assert resolve_api_key() == ("tc_agent_fromtcenv_00000000000", "tc-cli-env")
    monkeypatch.setenv("THREATCLUSTER_API_KEY", " tc_live_fromenv_0000000000000 ")
    assert resolve_api_key() == ("tc_live_fromenv_0000000000000", "env")


def test_resolve_key_via_tc_cli_module(monkeypatch, tmp_path):
    import types
    monkeypatch.delenv("THREATCLUSTER_API_KEY", raising=False)
    monkeypatch.delenv("TC_REFRESH_TOKEN", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    fake_pkg = types.ModuleType("tc_cli")
    fake_cred = types.ModuleType("tc_cli.credentials")
    fake_cred.load = lambda: "tc_agent_fromkeyring_000000000"
    fake_pkg.credentials = fake_cred
    monkeypatch.setitem(__import__("sys").modules, "tc_cli", fake_pkg)
    monkeypatch.setitem(__import__("sys").modules, "tc_cli.credentials", fake_cred)
    assert resolve_api_key() == ("tc_agent_fromkeyring_000000000", "tc-cli")


def test_base_and_site_env(monkeypatch):
    monkeypatch.setenv("THREATCLUSTER_API_BASE", "http://127.0.0.1:9/api/public/v1/")
    monkeypatch.setenv("THREATCLUSTER_SITE", "http://site/")
    assert C.resolve_api_base() == "http://127.0.0.1:9/api/public/v1"
    assert C.resolve_site() == "http://site"
