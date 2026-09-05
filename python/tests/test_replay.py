"""Every tool, both servers, against the recorded API responses; outputs must
equal the recorded python outputs (regression) and each other (parity)."""
import json

import pytest

from mcp_driver import FIXTURES, available_servers, call_tools, list_tools, server_env, stable, with_session
from replay_server import RecordReplayServer

API_FIXTURE = FIXTURES / "api.json"
TOOL_FIXTURES = sorted((FIXTURES / "tools").glob("*.json"))
FAKE_KEY = "tc_live_replay_key_000000000000000000"


def load_cases():
    """Recorded cases in the order they were recorded (budget headers depend on it)."""
    return sorted((json.loads(p.read_text(encoding="utf-8")) for p in TOOL_FIXTURES), key=lambda c: c["seq"])


@pytest.fixture(scope="module")
def replay():
    if not API_FIXTURE.exists():
        pytest.skip("no recorded fixtures; run THREATCLUSTER_LIVE=1 pytest tests/test_live.py")
    srv = RecordReplayServer(API_FIXTURE, mode="replay").start()
    yield srv
    srv.stop()


@pytest.mark.parametrize("kind", available_servers())
async def test_list_tools_matches_spec(kind, tmp_home, spec):
    env = server_env(tmp_home, api_base="http://127.0.0.1:9/api/public/v1", api_key=FAKE_KEY)
    tools = await list_tools(kind, env)
    expected = [{"name": t["name"], "title": t["title"], "description": t["description"], "inputSchema": t["inputSchema"],
                 "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}}
                for t in spec["tools"]]
    assert tools == expected


@pytest.mark.parametrize("kind", available_servers())
async def test_server_info_and_prompts(kind, tmp_home, spec):
    env = server_env(tmp_home, api_base="http://127.0.0.1:9/api/public/v1", api_key=FAKE_KEY)

    async def _fn(s, init):
        prompts = await s.list_prompts()
        got = await s.get_prompt("threatcluster_analyst", {"question": "what is new today?"})
        return init, prompts, got

    init, prompts, got = await with_session(kind, env, _fn)
    assert init.serverInfo.name == "threatcluster"
    assert init.serverInfo.version.count(".") == 2
    assert init.instructions == spec["server"]["instructions"]
    assert [p.name for p in prompts.prompts] == ["threatcluster_analyst"]
    text = got.messages[0].content.text
    assert "(UTC)" in text and text.endswith("Question: what is new today?") and "{today}" not in text


@pytest.mark.parametrize("kind", available_servers())
async def test_every_tool_replays_identically(kind, tmp_home, replay):
    cases = load_cases()
    assert len(cases) >= 10, "expected at least one recorded case per tool"
    env = server_env(tmp_home, api_base=replay.api_base, api_key=FAKE_KEY)
    results = await call_tools(kind, env, [{"name": c["name"], "args": c["args"]} for c in cases])
    problems = []
    for case, res in zip(cases, results):
        if res["is_error"] != case["expected"]["is_error"]:
            problems.append(f"{case['id']}: is_error {res['is_error']} != {case['expected']['is_error']}: {res['text'][:200]}")
            continue
        if res["is_error"]:
            if res["text"] != case["expected"]["text"]:
                problems.append(f"{case['id']}: error text differs:\n  got {res['text']}\n  exp {case['expected']['text']}")
            continue
        got, exp = stable(res["structured"]), stable(case["expected"]["structured"])
        if got != exp:
            problems.append(f"{case['id']}: output differs\n  got {json.dumps(got)[:600]}\n  exp {json.dumps(exp)[:600]}")
        # structuredContent must carry the same object as the text content
        if res["structured_content"] is not None and stable(res["structured_content"]) != got:
            problems.append(f"{case['id']}: structuredContent != text content")
    assert not problems, "\n".join(problems)
    assert replay.misses == [], f"{kind} requested URLs the recording never saw (request parity broken): {replay.misses}"


def test_fixtures_contain_no_credentials():
    """Recordings must never carry a key or bearer, whatever the API echoed."""
    import re
    for p in [API_FIXTURE, *TOOL_FIXTURES]:
        if not p.exists():
            continue
        raw = p.read_text(encoding="utf-8")
        assert not re.search(r"tc_(live|agent)_[A-Za-z0-9_\-]{6,}", raw), p
        assert not re.search(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.", raw), p  # JWT shape
