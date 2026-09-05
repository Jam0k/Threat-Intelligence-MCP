import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HERE, ROOT, SPEC } from "./helpers.mjs";
import { loadSpec, SpecSchema, toolSpecs } from "../dist/tools.js";

test("node/tools.json is byte-identical to tools/tools.json", () => {
  assert.equal(readFileSync(join(HERE, "..", "tools.json"), "utf8"), readFileSync(join(ROOT, "tools", "tools.json"), "utf8"));
});

test("spec parses under the strict zod schema and matches the file", () => {
  assert.deepEqual(loadSpec(), SPEC);
  assert.doesNotThrow(() => SpecSchema.parse(SPEC));
  assert.throws(() => SpecSchema.parse({ ...SPEC, tools: [{ ...SPEC.tools[0], extra: 1 }] }));
});

test("tool list and order", () => {
  assert.deepEqual(toolSpecs().map((t) => t.name), ["search_threats", "search_everything", "newest_threats", "get_threat",
    "leak_site_victims", "lookup_entity", "get_vulnerability", "exploited_vulnerabilities", "trending_entities", "api_budget"]);
});
