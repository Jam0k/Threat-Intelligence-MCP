"""tools/tools.json is the single source of truth; both package copies must be
byte-identical and the spec must be well-formed."""
import json
import re

PUBLIC_ENDPOINTS = {  # GET endpoints of the public API this server may use
    "/threats", "/threats/{identifier}", "/threats/{identifier}/iocs", "/search", "/darkweb/ransomware/victims",
    "/darkweb/ransomware/victims/facets", "/entities/search", "/entities/{type}/{value}", "/entities/trending",
    "/vulnerabilities", "/vulnerabilities/{cve_id}",
}
EXPECTED_TOOLS = ["search_threats", "search_everything", "newest_threats", "get_threat", "leak_site_victims", "lookup_entity",
                  "get_vulnerability", "exploited_vulnerabilities", "trending_entities", "api_budget"]


def test_copies_are_identical(root):
    src = (root / "tools" / "tools.json").read_bytes()
    assert (root / "python" / "src" / "threatcluster_mcp" / "tools.json").read_bytes() == src
    assert (root / "node" / "tools.json").read_bytes() == src


def test_package_loads_the_same_spec(spec):
    from threatcluster_mcp.tools import load_spec
    assert load_spec() == spec


def test_tool_list_and_order(spec):
    assert [t["name"] for t in spec["tools"]] == EXPECTED_TOOLS


def test_tools_well_formed(spec):
    names = set()
    for t in spec["tools"]:
        assert re.fullmatch(r"[a-z_]+", t["name"])
        assert t["name"] not in names
        names.add(t["name"])
        assert len(t["description"]) >= 40
        s = t["inputSchema"]
        assert s["type"] == "object" and s["additionalProperties"] is False
        assert set(s["required"]) <= set(s["properties"])
        for pname, ps in s["properties"].items():
            assert ps["type"] in ("string", "integer", "boolean", "array")
            if ps["type"] == "integer":
                assert "minimum" in ps and "maximum" in ps, f"{t['name']}.{pname} needs bounds"
            if ps["type"] == "string" and "enum" not in ps and "pattern" not in ps:
                assert "maxLength" in ps, f"{t['name']}.{pname} needs maxLength"
            if ps["type"] == "array":
                assert "maxItems" in ps and "items" in ps
            if "default" in ps:
                assert pname not in s["required"]
        assert isinstance(t["credits_max"], int)
        for ep in t["endpoints"]:
            method, path = ep.split(" ", 1)
            assert method == "GET"
            assert path.split("?")[0] in PUBLIC_ENDPOINTS, ep


def test_prompt_template_placeholders(spec):
    p = spec["prompts"][0]
    assert p["name"] == "threatcluster_analyst"
    assert "{today}" in p["template"] and "{question_block}" in p["template"]
    assert "url" in p["template"]  # citation rule adapted to URLs


def test_json_is_pretty_and_utf8(root):
    raw = (root / "tools" / "tools.json").read_text(encoding="utf-8")
    json.loads(raw)
    assert raw.endswith("}\n")
