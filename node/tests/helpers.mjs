// Shared helpers for the node test suite: replay server, scripted server,
// MCP client driver and the volatile-field stripper (mirrors python/tests).
import { createServer } from "node:http";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, "..", "..");
export const FIXTURES = join(ROOT, "tests", "fixtures");
export const ENTRY = join(HERE, "..", "dist", "index.js");
export const SPEC = JSON.parse(readFileSync(join(ROOT, "tools", "tools.json"), "utf8"));
const API_PREFIX = "/api/public/v1";

export function canonicalKey(pathname, search) {
  const rel = pathname.startsWith(API_PREFIX) ? pathname.slice(API_PREFIX.length) : pathname;
  const pairs = [...new URLSearchParams(search).entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return `GET ${rel}` + (pairs.length ? "?" + pairs.map(([k, v]) => `${k}=${v}`).join("&") : "");
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

/** Serves recorded responses from tests/fixtures/api.json; misses are 404 and collected. */
export async function startReplayServer() {
  const data = JSON.parse(readFileSync(join(FIXTURES, "api.json"), "utf8")).responses;
  const misses = [];
  const hits = [];
  const server = createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const key = canonicalKey(u.pathname, u.search);
    const entry = data[key];
    if (!entry) {
      misses.push(key);
      const body = JSON.stringify({ error: "replay miss", key });
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(body);
      return;
    }
    hits.push(key);
    const body = entry.json === false ? String(entry.body) : JSON.stringify(entry.body);
    res.writeHead(entry.status, { ...entry.headers });
    res.end(body);
  });
  await listen(server);
  return { server, misses, hits, apiBase: `http://127.0.0.1:${server.address().port}${API_PREFIX}`, close: () => server.close() };
}

/** Answers everything with one scripted response; records requests + headers. */
export async function startScriptedServer(status, body, headers = {}) {
  const requests = [];
  const seenHeaders = [];
  const server = createServer((req, res) => {
    requests.push(req.url);
    seenHeaders.push({ ...req.headers });
    res.writeHead(status, { "Content-Type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  });
  await listen(server);
  return { server, requests, seenHeaders, apiBase: `http://127.0.0.1:${server.address().port}${API_PREFIX}`, close: () => server.close() };
}

export function serverEnv({ apiBase, apiKey, site = "https://threatcluster.io" }) {
  const home = mkdtempSync(join(tmpdir(), "tcmcp-"));
  const env = {};
  for (const k of ["PATH", "LANG", "LC_ALL", "SYSTEMROOT", "TMPDIR"]) if (process.env[k]) env[k] = process.env[k];
  env.HOME = home;
  env.XDG_CONFIG_HOME = join(home, "xdg");
  env.THREATCLUSTER_API_BASE = apiBase;
  env.THREATCLUSTER_SITE = site;
  if (apiKey) env.THREATCLUSTER_API_KEY = apiKey;
  return env;
}

export async function withClient(env, fn) {
  const transport = new StdioClientTransport({ command: "node", args: [ENTRY], env, stderr: "ignore" });
  const client = new Client({ name: "threatcluster-mcp-tests", version: "0" });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

export async function callTools(env, calls) {
  return withClient(env, async (client) => {
    const out = [];
    for (const c of calls) {
      const res = await client.callTool({ name: c.name, arguments: c.args || {} });
      const text = (res.content || []).map((b) => b.text || "").join("");
      let structured = null;
      if (!res.isError) {
        try { structured = JSON.parse(text); } catch { structured = null; }
      }
      out.push({ is_error: Boolean(res.isError), text, structured, structured_content: res.structuredContent ?? null });
    }
    return out;
  });
}

export function stable(result) {
  const r = JSON.parse(JSON.stringify(result));
  if (!r || typeof r !== "object") return r;
  delete r.as_of;
  if (r.tool === "api_budget") {
    delete r.api_base;
    if (r.session) { delete r.session.started_at; delete r.session.requests_last_minute; }
    if (r.last_response) delete r.last_response.at;
  }
  return r;
}

export function loadCases() {
  const dir = join(FIXTURES, "tools");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => f.endsWith(".json")).map((f) => JSON.parse(readFileSync(join(dir, f), "utf8"))).sort((a, b) => a.seq - b.seq);
}

/** Raw newline-delimited JSON-RPC; returns every byte of stdout and stderr. */
export function rawJsonRpc(env, requests, timeoutMs = 60000) {
  return new Promise((resolve, reject) => {
    const proc = spawn("node", [ENTRY], { env, stdio: ["pipe", "pipe", "pipe"] });
    const out = [];
    const err = [];
    proc.stdout.on("data", (d) => out.push(d));
    proc.stderr.on("data", (d) => err.push(d));
    const timer = setTimeout(() => { proc.kill(); reject(new Error("timeout")); }, timeoutMs);
    proc.on("close", () => { clearTimeout(timer); resolve({ out: Buffer.concat(out), err: Buffer.concat(err) }); });
    // Send everything, then wait for a response id == last id before closing stdin.
    const lastId = [...requests].reverse().find((r) => r.id !== undefined)?.id;
    let buffer = "";
    proc.stdout.on("data", (d) => {
      buffer += d.toString();
      if (buffer.split("\n").some((l) => { try { return JSON.parse(l).id === lastId; } catch { return false; } })) proc.stdin.end();
    });
    for (const r of requests) proc.stdin.write(JSON.stringify(r) + "\n");
  });
}
