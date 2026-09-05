import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ApiError, ThreatClusterClient, resolveApiKey, scrubKeyShapes } from "../dist/client.js";

const KEY = "tc_live_unitTESTkey_0123456789abcdef0123456789";
const mk = (fetchImpl, key = KEY) => new ThreatClusterClient(key, { base: "https://api.test/api/public/v1", site: "https://site.test", keySource: "env", fetchImpl });
const resp = (status, body, headers = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers });

test("auth header: X-API-Key for tc_ keys, Bearer otherwise; None params dropped", async () => {
  const seen = [];
  const f = async (url, init) => { seen.push({ url, headers: init.headers }); return resp(200, { ok: true }, { "X-Request-Cost": "1" }); };
  const [body, cost] = await mk(f).get("/threats", { limit: 3, keyword: null, x: "" });
  assert.deepEqual(body, { ok: true }); assert.equal(cost, 1);
  assert.equal(seen[0].url, "https://api.test/api/public/v1/threats?limit=3");
  assert.equal(seen[0].headers["X-API-Key"], KEY); assert.equal(seen[0].headers.Authorization, undefined);
  assert.equal(seen[0].headers.Accept, "application/json");
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig";
  await mk(f, jwt).get("/threats");
  assert.equal(seen[1].headers.Authorization, "Bearer " + jwt); assert.equal(seen[1].headers["X-API-Key"], undefined);
});

test("budget headers parsed", async () => {
  const c = mk(async () => resp(200, {}, { "X-Request-Cost": "5", "X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "80", "X-RateLimit-Reset": "1788566400" }));
  await c.get("/search", { q: "lockbit" });
  assert.deepEqual(c.budget.brief(), { remaining: 80, limit: 100, resets_at: "2026-09-05T00:00:00Z" });
  const s = c.budget.snapshot();
  assert.equal(s.session.credits_spent, 5); assert.equal(s.last_response.status, 200); assert.equal(s.last_error, null);
});

const cases = [
  [401, { error: "Unauthorized", detail: "Authentication required" }, {}, "Unauthorized", "THREATCLUSTER_API_KEY", null],
  [403, { detail: { error: "insufficient_scope", message: "needs scope", required_scope: "mssp:read", granted_scopes: ["threats:read"] } }, {}, "insufficient_scope", "mssp:read", null],
  [403, { detail: { error: "lookback_exceeded", message: "older", lookback_days: 7 } }, {}, "lookback_exceeded", "last 7 days", null],
  [404, { error: "Endpoint not found" }, {}, "not_found", "nothing matches /threats/zzz", null],
  [429, { detail: { error: "rate_limit_exceeded", message: "30/min", retry_after: 17 } }, { "Retry-After": "17" }, "rate_limit_exceeded", "Retry after 17 seconds", 17],
  [429, { detail: { error: "daily_budget_exceeded", message: "100/day" } }, { "Retry-After": "3600" }, "daily_budget_exceeded", "00:00 UTC", 3600],
  [429, "slow down", {}, "rate_limited", "Retry after 60 seconds", 60],
  [500, "boom", {}, "server_error", "retry once", null],
];
for (const [status, body, headers, code, frag, retry] of cases) {
  test(`error mapping ${status} ${code}`, async () => {
    const c = mk(async () => resp(status, body, headers));
    await assert.rejects(c.get("/threats/zzz"), (e) => {
      assert.ok(e instanceof ApiError); assert.equal(e.status, status); assert.equal(e.code, code); assert.equal(e.retryAfter, retry);
      assert.ok(e.toText().includes(frag), e.toText()); assert.ok(!e.toText().includes(KEY));
      assert.deepEqual(c.budget.lastError, e.toDict());
      return true;
    });
  });
}

test("network / non-JSON / timeout errors are scrubbed", async () => {
  await assert.rejects(mk(async () => { throw new TypeError(`fetch failed for ${KEY}`); }).get("/threats"),
    (e) => e.code === "network_error" && !e.toText().includes(KEY) && e.toText().includes("[redacted]"));
  await assert.rejects(mk(async () => resp(200, "<html>")).get("/threats"), (e) => e.code === "bad_response");
  await assert.rejects(mk(async () => { const e = new Error("t"); e.name = "TimeoutError"; throw e; }).get("/threats"), (e) => e.code === "timeout");
});

test("redact and scrub", () => {
  const c = new ThreatClusterClient(KEY, { keySource: "env" });
  assert.equal(c.redact(`header X-API-Key: ${KEY} sent`), "header X-API-Key: [redacted] sent");
  assert.equal(c.redact(null), "");
  assert.equal(new ThreatClusterClient("short", { keySource: "env" }).redact("short key stays"), "short key stays");
  assert.equal(scrubKeyShapes("k=tc_agent_abcdefghijklmnop rest"), "k=tc_[redacted] rest");
});

test("resolveApiKey precedence and file policy", () => {
  const saved = { ...process.env };
  try {
    delete process.env.THREATCLUSTER_API_KEY; delete process.env.TC_REFRESH_TOKEN;
    const xdg = mkdtempSync(join(tmpdir(), "tcmcp-xdg-"));
    process.env.XDG_CONFIG_HOME = xdg;
    assert.deepEqual(resolveApiKey(), { key: null, source: "none" });
    mkdirSync(join(xdg, "tc-cli"));
    const f = join(xdg, "tc-cli", "credentials");
    writeFileSync(f, "tc_live_fromfile_000000000000\n");
    chmodSync(f, 0o644);
    assert.deepEqual(resolveApiKey(), { key: null, source: "none" });
    chmodSync(f, 0o600);
    assert.deepEqual(resolveApiKey(), { key: "tc_live_fromfile_000000000000", source: "tc-cli-file" });
    process.env.TC_REFRESH_TOKEN = "tc_agent_fromtcenv_00000000000";
    assert.deepEqual(resolveApiKey(), { key: "tc_agent_fromtcenv_00000000000", source: "tc-cli-env" });
    process.env.THREATCLUSTER_API_KEY = " tc_live_fromenv_0000000000000 ";
    assert.deepEqual(resolveApiKey(), { key: "tc_live_fromenv_0000000000000", source: "env" });
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
