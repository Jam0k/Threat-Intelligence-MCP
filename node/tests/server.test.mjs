import test from "node:test";
import assert from "node:assert/strict";
import { SPEC, callTools, loadCases, rawJsonRpc, serverEnv, stable, startReplayServer, startScriptedServer, withClient } from "./helpers.mjs";

const FAKE_KEY = "tc_live_replay_key_000000000000000000";
const CANARY = "tc_live_LEAKCANARY_0123456789abcdef0123456789abcdef";
const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

test("list_tools matches tools.json exactly; server info + prompt", async () => {
  const env = serverEnv({ apiBase: "http://127.0.0.1:9/api/public/v1", apiKey: FAKE_KEY });
  await withClient(env, async (client) => {
    const { tools } = await client.listTools();
    const expected = SPEC.tools.map((t) => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: ANNOTATIONS }));
    assert.deepEqual(tools, expected);
    const v = client.getServerVersion();
    assert.equal(v.name, "threatcluster"); assert.equal(v.version.split(".").length, 3);
    assert.equal(client.getInstructions(), SPEC.server.instructions);
    const { prompts } = await client.listPrompts();
    assert.deepEqual(prompts.map((p) => p.name), ["threatcluster_analyst"]);
    const got = await client.getPrompt({ name: "threatcluster_analyst", arguments: { question: "what is new today?" } });
    const text = got.messages[0].content.text;
    assert.ok(text.includes("(UTC)") && text.endsWith("Question: what is new today?") && !text.includes("{today}"));
  });
});

test("every recorded tool call replays identically (regression + parity with python)", async () => {
  const cases = loadCases();
  assert.ok(cases.length >= 10, "no recorded fixtures; run the python live test first");
  const replay = await startReplayServer();
  try {
    const env = serverEnv({ apiBase: replay.apiBase, apiKey: FAKE_KEY });
    const results = await callTools(env, cases.map((c) => ({ name: c.name, args: c.args })));
    const problems = [];
    cases.forEach((c, i) => {
      const r = results[i];
      if (r.is_error !== c.expected.is_error) { problems.push(`${c.id}: is_error ${r.is_error} != ${c.expected.is_error}: ${r.text.slice(0, 200)}`); return; }
      if (r.is_error) { if (r.text !== c.expected.text) problems.push(`${c.id}: error text differs: ${r.text}`); return; }
      const got = stable(r.structured), exp = stable(c.expected.structured);
      try { assert.deepEqual(got, exp); } catch (e) { problems.push(`${c.id}: output differs: ${e.message.slice(0, 800)}`); }
      if (r.structured_content !== null) { try { assert.deepEqual(stable(r.structured_content), got); } catch { problems.push(`${c.id}: structuredContent != text`); } }
    });
    assert.deepEqual(problems, []);
    assert.deepEqual(replay.misses, [], "node requested URLs the recording never saw");
  } finally {
    replay.close();
  }
});

test("401 maps to the key hint and the key goes out in exactly one header", async () => {
  const srv = await startScriptedServer(401, { error: "Unauthorized", detail: "Authentication required" });
  try {
    const env = serverEnv({ apiBase: srv.apiBase, apiKey: CANARY });
    const [r, b] = await callTools(env, [{ name: "newest_threats", args: { limit: 2 } }, { name: "api_budget" }]);
    assert.ok(r.is_error && r.text.includes("401") && r.text.includes("THREATCLUSTER_API_KEY") && r.text.includes("threatcluster.io/api"));
    assert.ok(!r.text.includes(CANARY));
    assert.equal(srv.seenHeaders[0]["x-api-key"], CANARY);
    assert.equal(srv.seenHeaders[0].authorization, undefined);
    assert.equal(b.structured.last_error.status, 401); assert.equal(b.structured.session.credits_spent, 0);
  } finally { srv.close(); }
});

test("429 carries Retry-After; daily budget exhaustion is explained", async () => {
  let srv = await startScriptedServer(429, { detail: { error: "rate_limit_exceeded", message: "30/min", retry_after: 23 } }, { "Retry-After": "23" });
  try {
    const [r] = await callTools(serverEnv({ apiBase: srv.apiBase, apiKey: CANARY }), [{ name: "search_everything", args: { query: "lockbit" } }]);
    assert.ok(r.is_error && r.text.includes("429 rate_limit_exceeded") && r.text.includes("Retry after 23 seconds"), r.text);
  } finally { srv.close(); }
  srv = await startScriptedServer(429, { detail: { error: "daily_budget_exceeded", message: "Free keys get 100 credits a day" } },
    { "Retry-After": "1200", "X-RateLimit-Remaining": "0", "X-RateLimit-Limit": "100", "X-RateLimit-Reset": "1788566400", "X-Request-Cost": "5" });
  try {
    const [r, b] = await callTools(serverEnv({ apiBase: srv.apiBase, apiKey: CANARY }), [{ name: "search_everything", args: { query: "lockbit" } }, { name: "api_budget" }]);
    assert.ok(r.is_error && r.text.includes("daily_budget_exceeded") && r.text.includes("Retry after 1200 seconds") && r.text.includes("00:00 UTC"));
    assert.equal(b.structured.daily_credits.remaining, 0);
  } finally { srv.close(); }
});

test("403 scope names the scope and the plan", async () => {
  const srv = await startScriptedServer(403, { detail: { error: "insufficient_scope", message: "needs", required_scope: "darkweb:read", granted_scopes: ["threats:read"] } });
  try {
    const [r] = await callTools(serverEnv({ apiBase: srv.apiBase, apiKey: CANARY }), [{ name: "leak_site_victims" }]);
    assert.ok(r.is_error && r.text.includes("403 insufficient_scope") && r.text.includes("darkweb:read") && r.text.includes("pricing"));
  } finally { srv.close(); }
});

test("no key configured: clear error, no request made", async () => {
  const srv = await startScriptedServer(200, { threats: [] });
  try {
    const [r, b] = await callTools(serverEnv({ apiBase: srv.apiBase, apiKey: null }), [{ name: "newest_threats" }, { name: "api_budget" }]);
    assert.ok(r.is_error && r.text.includes("THREATCLUSTER_API_KEY") && r.text.includes("tc auth login"));
    assert.deepEqual(srv.requests, []);
    assert.equal(b.structured.key_configured, false); assert.equal(b.structured.key_source, "none");
  } finally { srv.close(); }
});

test("the key never reaches stdout or stderr", async () => {
  const srv = await startScriptedServer(401, { error: "Unauthorized", detail: `Authentication required; you sent ${CANARY}` });
  try {
    const env = serverEnv({ apiBase: srv.apiBase, apiKey: CANARY });
    const msgs = [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "leak-test", version: "0" } } },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "search_threats", arguments: { query: CANARY } } },
      { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "search_threats", arguments: { query: "x", bogus: CANARY } } },
      { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "api_budget", arguments: {} } },
      { jsonrpc: "2.0", id: 6, method: "prompts/get", params: { name: "threatcluster_analyst", arguments: { question: CANARY } } },
    ];
    const { out, err } = await rawJsonRpc(env, msgs);
    assert.ok(out.length > 0);
    assert.ok(!out.includes(CANARY), "API key leaked to stdout (MCP transport)");
    assert.ok(!err.includes(CANARY), "API key leaked to stderr");
    assert.ok(out.includes("[redacted]"));
  } finally { srv.close(); }
});
