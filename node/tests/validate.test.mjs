import test from "node:test";
import assert from "node:assert/strict";
import { ToolInputError, toolSpec, validateArgs } from "../dist/tools.js";

const schema = (n) => toolSpec(n).inputSchema;
const fails = (n, args, msg) => {
  assert.throws(() => validateArgs(schema(n), args), (e) => e instanceof ToolInputError && e.message === msg, `${JSON.stringify(args)} -> ${msg}`);
};

test("defaults filled", () => {
  assert.deepEqual(validateArgs(schema("search_threats"), { query: "lockbit" }), { query: "lockbit", limit: 8 });
  assert.deepEqual(validateArgs(schema("newest_threats"), {}), { time_filter: "24h", limit: 12, sort_by: "new" });
  assert.deepEqual(validateArgs(schema("api_budget"), undefined), {});
});

test("error messages match the python package", () => {
  fails("search_threats", {}, "missing required argument 'query'");
  fails("search_threats", { query: null }, "missing required argument 'query'");
  fails("search_threats", { query: "x", zzz: 1 }, "unknown argument 'zzz'");
  fails("search_threats", { query: "x", days: 0 }, "argument 'days' must be an integer between 1 and 90");
  fails("search_threats", { query: "x", days: 91 }, "argument 'days' must be an integer between 1 and 90");
  fails("search_threats", { query: "x", limit: 2.5 }, "argument 'limit' must be an integer");
  fails("search_threats", { query: "x", limit: true }, "argument 'limit' must be an integer");
  fails("search_threats", { query: "x", limit: "3" }, "argument 'limit' must be an integer");
  fails("search_threats", { query: 5 }, "argument 'query' must be a string");
  fails("search_threats", { query: "" }, "argument 'query' must be between 1 and 200 characters");
  fails("search_threats", { query: "x", alternatives: "y" }, "argument 'alternatives' must be a list");
  fails("search_threats", { query: "x", alternatives: ["a", "a", "a", "a", "a", "a"] }, "argument 'alternatives' must be a list of at most 5 items");
  fails("search_threats", { query: "x", alternatives: ["a", 2] }, "argument 'alternatives[1]' must be a string");
  fails("newest_threats", { time_filter: "90d" }, "argument 'time_filter' must be one of: 1h, 24h, 7d, 30d");
  fails("get_threat", { identifier: "abcd1234", include_iocs: "yes" }, "argument 'include_iocs' must be true or false");
  fails("api_budget", [1], "arguments must be an object");
  assert.throws(() => validateArgs(schema("get_vulnerability"), { cve_id: "2026-1234" }), /does not match the expected format/);
  assert.deepEqual(validateArgs(schema("get_vulnerability"), { cve_id: "cve-2026-83549" }), { cve_id: "cve-2026-83549" });
  assert.throws(() => validateArgs(schema("leak_site_victims"), { country: "USA" }));
  assert.equal(validateArgs(schema("newest_threats"), { limit: 3.0 }).limit, 3);
});
