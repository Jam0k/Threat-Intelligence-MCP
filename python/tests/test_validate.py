import pytest

from threatcluster_mcp.tools import ToolInputError, tool_spec, validate_args


def schema(name):
    return tool_spec(name)["inputSchema"]


def test_defaults_filled():
    assert validate_args(schema("search_threats"), {"query": "lockbit"}) == {"query": "lockbit", "limit": 8}
    assert validate_args(schema("newest_threats"), {}) == {"time_filter": "24h", "limit": 12, "sort_by": "new"}
    assert validate_args(schema("api_budget"), None) == {}


@pytest.mark.parametrize("args,msg", [
    ({}, "missing required argument 'query'"),
    ({"query": None}, "missing required argument 'query'"),
    ({"query": "x", "zzz": 1}, "unknown argument 'zzz'"),
    ({"query": "x", "days": 0}, "argument 'days' must be an integer between 1 and 90"),
    ({"query": "x", "days": 91}, "argument 'days' must be an integer between 1 and 90"),
    ({"query": "x", "limit": 2.5}, "argument 'limit' must be an integer"),
    ({"query": "x", "limit": True}, "argument 'limit' must be an integer"),
    ({"query": "x", "limit": "3"}, "argument 'limit' must be an integer"),
    ({"query": 5}, "argument 'query' must be a string"),
    ({"query": ""}, "argument 'query' must be between 1 and 200 characters"),
    ({"query": "x", "alternatives": "y"}, "argument 'alternatives' must be a list"),
    ({"query": "x", "alternatives": ["a"] * 6}, "argument 'alternatives' must be a list of at most 5 items"),
    ({"query": "x", "alternatives": ["a", 2]}, "argument 'alternatives[1]' must be a string"),
])
def test_search_threats_errors(args, msg):
    with pytest.raises(ToolInputError) as e:
        validate_args(schema("search_threats"), args)
    assert str(e.value) == msg


def test_enum_and_pattern():
    with pytest.raises(ToolInputError) as e:
        validate_args(schema("newest_threats"), {"time_filter": "90d"})
    assert str(e.value) == "argument 'time_filter' must be one of: 1h, 24h, 7d, 30d"
    with pytest.raises(ToolInputError) as e:
        validate_args(schema("get_vulnerability"), {"cve_id": "2026-1234"})
    assert str(e.value).startswith("argument 'cve_id' does not match the expected format")
    assert validate_args(schema("get_vulnerability"), {"cve_id": "cve-2026-83549"}) == {"cve_id": "cve-2026-83549"}
    with pytest.raises(ToolInputError):
        validate_args(schema("leak_site_victims"), {"country": "USA"})
    assert validate_args(schema("leak_site_victims"), {"country": "gb"})["country"] == "gb"


def test_boolean_and_float_integer():
    with pytest.raises(ToolInputError) as e:
        validate_args(schema("get_threat"), {"identifier": "abcd1234", "include_iocs": "yes"})
    assert str(e.value) == "argument 'include_iocs' must be true or false"
    # JSON clients sometimes send 3.0 for 3; accept whole floats.
    assert validate_args(schema("newest_threats"), {"limit": 3.0})["limit"] == 3


def test_not_an_object():
    with pytest.raises(ToolInputError) as e:
        validate_args(schema("api_budget"), [1])
    assert str(e.value) == "arguments must be an object"
