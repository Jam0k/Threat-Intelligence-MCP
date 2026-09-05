"""LIVE validation and fixture recording. Runs only with

    THREATCLUSTER_LIVE=1 THREATCLUSTER_API_KEY=<free-tier key or bearer> \
    THREATCLUSTER_API_BASE=http://127.0.0.1:8765/api/public/v1 pytest tests/test_live.py -s

Drives the PYTHON server through a recording proxy against the real API
(spending ~25 credits), asserts every tool returns a well-shaped, non-empty
result, then drives the NODE server against the recording (replay) and
asserts it produced byte-equal results from byte-equal requests. Writes
tests/fixtures/api.json, tests/fixtures/tools/*.json and live_report.json."""
import json
import os
import re
from datetime import datetime, timezone

import pytest

from mcp_driver import FIXTURES, NODE_ENTRY, call_tools, server_env, stable
from replay_server import RecordReplayServer

LIVE = os.environ.get("THREATCLUSTER_LIVE") == "1" and os.environ.get("THREATCLUSTER_API_KEY") and os.environ.get("THREATCLUSTER_API_BASE")
pytestmark = pytest.mark.skipif(not LIVE, reason="set THREATCLUSTER_LIVE=1 + THREATCLUSTER_API_KEY + THREATCLUSTER_API_BASE")
SITE = "https://threatcluster.io"

# The plan. "$..." values are resolved from earlier results at run time.
PLAN = [
    {"id": "api_budget_before", "name": "api_budget", "args": {}},
    {"id": "search_threats", "name": "search_threats", "args": {"query": "Cleo Harmony", "days": 7, "limit": 3}},
    {"id": "search_threats_alternatives", "name": "search_threats", "args": {"query": "ransomware", "alternatives": ["extortion"], "limit": 4}},
    {"id": "search_threats_miss", "name": "search_threats", "args": {"query": "zzqx-nonexistent-term", "days": 3, "limit": 2}},
    {"id": "search_everything", "name": "search_everything", "args": {"query": "lockbit", "limit": 3}},
    {"id": "newest_threats", "name": "newest_threats", "args": {"time_filter": "24h", "limit": 3, "sort_by": "new"}},
    {"id": "newest_threats_trending", "name": "newest_threats", "args": {"time_filter": "7d", "limit": 2, "sort_by": "trending"}},
    {"id": "get_threat", "name": "get_threat", "args": {"identifier": "$cluster_slug", "include_iocs": True}},
    {"id": "get_threat_short_id", "name": "get_threat", "args": {"identifier": "$cluster_short_id"}},
    {"id": "get_threat_404", "name": "get_threat", "args": {"identifier": "does-not-exist-00000000"}},
    {"id": "leak_site_victims", "name": "leak_site_victims", "args": {"days": 7, "limit": 5}},
    {"id": "leak_site_victims_sector", "name": "leak_site_victims", "args": {"days": 7, "sector": "Healthcare", "limit": 3}},
    {"id": "leak_site_victims_victim", "name": "leak_site_victims", "args": {"days": 7, "victim": ".com", "limit": 3}},
    {"id": "lookup_entity", "name": "lookup_entity", "args": {"name": "lockbit"}},
    {"id": "lookup_entity_typed", "name": "lookup_entity", "args": {"name": "apt29", "entity_type": "apt_group"}},
    {"id": "lookup_entity_miss", "name": "lookup_entity", "args": {"name": "NoSuchEntityZZZ"}},
    {"id": "exploited_vulnerabilities", "name": "exploited_vulnerabilities", "args": {"days": 7, "kev_only": True, "limit": 3}},
    {"id": "get_vulnerability", "name": "get_vulnerability", "args": {"cve_id": "$cve_id"}},
    {"id": "get_vulnerability_404", "name": "get_vulnerability", "args": {"cve_id": "CVE-1999-99999"}},
    {"id": "trending_entities", "name": "trending_entities", "args": {"time_filter": "7d", "limit": 3}},
    {"id": "trending_entities_typed", "name": "trending_entities", "args": {"time_filter": "7d", "entity_types": ["malware", "ransomware_group"], "limit": 3}},
    {"id": "api_budget_after", "name": "api_budget", "args": {}},
]


def _resolve(args: dict, ctx: dict) -> dict:
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and v.startswith("$"):
            assert v[1:] in ctx, f"unresolved placeholder {v}"
            out[k] = ctx[v[1:]]
        else:
            out[k] = v
    return out


def _assert_shape(case_id: str, name: str, r: dict) -> None:
    """Non-empty, well-shaped, citable."""
    assert r["tool"] == name and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", r["as_of"])
    assert isinstance(r["cost"], int) and r["cost"] >= 0
    if name != "api_budget":
        assert r["budget"] and r["budget"]["limit"] == 100 and 0 <= r["budget"]["remaining"] <= 100
    if name == "search_threats":
        if case_id == "search_threats_miss":
            assert r["count"] == 0 and r["matched_stage"] is None and r["api_calls"] >= 1
        else:
            assert r["count"] >= 1 and r["matched_stage"] in ("phrase", "all words", "any word")
            assert r["cost"] >= 1 and r["api_calls"] <= 8
        for c in r["clusters"]:
            assert c["url"].startswith(SITE + "/cluster/") and c["title"] and c["cluster_id"]
    elif name == "search_everything":
        assert r["cost"] == 5 and (r["clusters"] or r["entities"] or r["darkweb"])
        for e in r["entities"]:
            assert e["url"].startswith(SITE + "/entities/")
    elif name == "newest_threats":
        assert r["cost"] == 1 and len(r["clusters"]) >= 1 and all(c["date"] for c in r["clusters"])
    elif name == "get_threat":
        assert r["url"].startswith(SITE + "/cluster/") and r["summary"] and r["timeline"] and r["articles"]
        assert all(a["url"] for a in r["articles"]) and r["entities"]
        if "iocs" in r:
            assert r["cost"] == 2 and "count" in r["iocs"] and isinstance(r["iocs"]["indicators"], list)
        else:
            assert r["cost"] == 1
    elif name == "leak_site_victims":
        assert r["cost"] == 2 and r["window_total_listings"] > 0 and r["by_group"] and r["by_sector"] and r["by_country"]
        assert r["listings"] and all(l["url"].startswith(SITE + "/dark-web/") and l["group"] and l["victim"] for l in r["listings"])
        if "sector" in r["filters"]:
            assert all(l["sector"] == "Healthcare" for l in r["listings"])
        if "victim" in r["filters"]:
            assert all(".com" in f"{l['victim']} {l['website']}".lower() for l in r["listings"])
    elif name == "lookup_entity":
        if case_id == "lookup_entity_miss":
            assert r["found"] is False and r["cost"] <= 1
        else:
            assert r["found"] and r["cost"] == 2 and r["entity"]["url"].startswith(SITE + "/entities/") and r["entity"]["mentions"]
            assert r["recent_clusters"] and r["related"]
    elif name == "get_vulnerability":
        assert r["cost"] == 1 and r["cve_id"].startswith("CVE-") and r["description"] and r["url"].endswith(r["cve_id"])
        assert "vector" in r["cvss"] and isinstance(r["references"], list)
    elif name == "exploited_vulnerabilities":
        assert r["cost"] == 1 and r["cves"] and all(c["in_kev"] for c in r["cves"]) and r["total"] >= len(r["cves"])
    elif name == "trending_entities":
        assert r["cost"] == 1 and r["entities"]
        if case_id == "trending_entities_typed":
            assert set(r["entities"]) <= {"malware", "ransomware_group"}
        else:
            assert not (set(r["entities"]) & {"ipv4", "sha256", "md5", "email", "domain"})
        for rows in r["entities"].values():
            assert all(x["url"].startswith(SITE + "/entities/") and x["mentions"] for x in rows)


async def test_live_record_and_parity(tmp_home):
    key = os.environ["THREATCLUSTER_API_KEY"]
    upstream = os.environ["THREATCLUSTER_API_BASE"]
    api_fixture = FIXTURES / "api.json"
    if api_fixture.exists():
        api_fixture.unlink()  # a live run re-records from scratch
    for p in (FIXTURES / "tools").glob("*.json"):
        p.unlink()
    proxy = RecordReplayServer(api_fixture, mode="record", upstream=upstream).start()
    report = {"recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "upstream": upstream, "python": {}, "node": {}}
    try:
        # ---- python, live through the recording proxy --------------------
        env = server_env(tmp_home, api_base=proxy.api_base, api_key=key, site=SITE)
        ctx: dict = {}
        cases: list[dict] = []
        results: list[dict] = []
        from mcp_driver import with_session

        async def _run(s, init):
            for seq, step in enumerate(PLAN):
                args = _resolve(step["args"], ctx)
                res = await s.call_tool(step["name"], args)
                text = "".join(getattr(b, "text", "") for b in res.content)
                structured = json.loads(text) if not res.isError else None
                cases.append({"seq": seq, "id": step["id"], "name": step["name"], "args": args,
                              "expected": {"is_error": bool(res.isError), "text": text if res.isError else None, "structured": structured}})
                results.append({"is_error": bool(res.isError), "text": text, "structured": structured})
                if step["id"] == "search_threats" and structured and structured["clusters"]:
                    top = structured["clusters"][0]
                    ctx["cluster_slug"] = top["url"].rsplit("/", 1)[1]
                    ctx["cluster_short_id"] = top["short_id"]
                if step["id"] == "exploited_vulnerabilities" and structured and structured["cves"]:
                    ctx["cve_id"] = structured["cves"][0]["cve_id"]
        await with_session("python", env, _run)

        problems = []
        spent = 0
        for case, res in zip(cases, results):
            cid, name = case["id"], case["name"]
            if cid.endswith("_404"):
                ok = res["is_error"] and "404 not_found" in res["text"]
                m = re.search(r"\(cost: (\d+) credits\)", res["text"])
                spent += int(m.group(1)) if m else 0
                report["python"][cid] = {"ok": ok, "error": res["text"], "cost": int(m.group(1)) if m else 0}
                if not ok:
                    problems.append(f"{cid}: expected a 404 tool error, got {res['text'][:200]}")
                continue
            if res["is_error"]:
                problems.append(f"{cid}: unexpected tool error: {res['text'][:300]}")
                report["python"][cid] = {"ok": False, "error": res["text"]}
                continue
            try:
                _assert_shape(cid, name, res["structured"])
                spent += res["structured"]["cost"]
                report["python"][cid] = {"ok": True, "cost": res["structured"]["cost"], "chars": len(res["text"])}
            except AssertionError as e:
                problems.append(f"{cid}: shape assertion failed: {e}")
                report["python"][cid] = {"ok": False, "error": str(e)}
        before = results[0]["structured"]
        after = results[-1]["structured"]
        assert before["session"]["api_calls"] == 0 and before["daily_credits"]["remaining"] is None
        assert after["session"]["credits_spent"] == spent, "api_budget must equal the sum of reported costs"
        assert after["session"]["api_calls"] == len(proxy.hits)
        assert after["daily_credits"]["remaining"] is not None and after["daily_credits"]["limit"] == 100
        assert after["last_error"] is None or after["last_error"]["status"] == 404
        assert not problems, "\n".join(problems)

        # ---- persist fixtures (no credentials inside) ------------------------
        proxy.save(report["recorded_at"])
        (FIXTURES / "tools").mkdir(parents=True, exist_ok=True)
        for case in cases:
            (FIXTURES / "tools" / f"{case['id']}.json").write_text(json.dumps(case, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        raw = api_fixture.read_text(encoding="utf-8")
        assert key not in raw and "tc_live_" not in raw and "tc_agent_" not in raw

        # ---- node, against the recording: same requests, same outputs ---------
        if NODE_ENTRY.exists():
            proxy.mode = "replay"
            proxy.misses.clear()
            node_env = server_env(tmp_home, api_base=proxy.api_base, api_key="tc_live_replay_key_000000000000000000", site=SITE)
            node_results = await call_tools("node", node_env, [{"name": c["name"], "args": c["args"]} for c in cases])
            diffs = []
            for case, py, nd in zip(cases, results, node_results):
                if nd["is_error"] != py["is_error"] or (nd["is_error"] and nd["text"] != py["text"]):
                    diffs.append(f"{case['id']}: node {nd['text'][:200]!r} vs python {py['text'][:200]!r}")
                elif not nd["is_error"] and stable(nd["structured"]) != stable(py["structured"]):
                    diffs.append(f"{case['id']}: outputs differ\n node   {json.dumps(stable(nd['structured']))[:500]}\n python {json.dumps(stable(py['structured']))[:500]}")
                report["node"][case["id"]] = {"ok": not diffs or diffs[-1].split(":")[0] != case["id"], "chars": len(nd["text"])}
            assert not diffs, "\n".join(diffs)
            assert proxy.misses == [], f"node issued requests python never did: {proxy.misses}"
        else:
            report["node"] = {"skipped": "node/dist/index.js not built"}
    finally:
        proxy.stop()
        (FIXTURES / "live_report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
