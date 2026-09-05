/**
 * HTTP client for the ThreatCluster public API.
 *
 * Security contract (mirrors python/src/threatcluster_mcp/client.py):
 *  - The API key is resolved once (env var first, then the tc-cli credential
 *    file), held on the client, and leaves the process in exactly one place:
 *    the `X-API-Key` header (or `Authorization: Bearer` for a JWT minted by
 *    `tc login`) of requests to the configured API base.
 *  - Never logged, never written to disk, never echoed in an error: every
 *    string that can reach the MCP transport goes through `redact()`.
 *  - No telemetry: the only network destination is THREATCLUSTER_API_BASE.
 *  - stdout is the MCP transport; this module never writes to it.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const DEFAULT_API_BASE = "https://threatcluster.io/api/public/v1";
export const DEFAULT_SITE = "https://threatcluster.io";
export const FREE_KEY_URL = "https://threatcluster.io/api";
export const PRICING_URL = "https://threatcluster.io/pricing";
export const ENV_API_KEY = "THREATCLUSTER_API_KEY";
export const ENV_API_BASE = "THREATCLUSTER_API_BASE";
export const ENV_SITE = "THREATCLUSTER_SITE";
export const ENV_TC_CLI_TOKEN = "TC_REFRESH_TOKEN";
export const REQUEST_TIMEOUT_MS = 45_000;

export type Json = any;

export function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function epochIso(epoch: number | null): string | null {
  if (epoch === null) return null;
  return new Date(epoch * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ---------------------------------------------------------------------------
// Credential resolution
// ---------------------------------------------------------------------------
function tcCliCredentialFile(): string {
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  return join(base, "tc-cli", "credentials");
}

function readTcCliFile(): string | null {
  // The 0600 file tc-cli falls back to when no keyring is available. Same
  // policy as tc_cli.credentials: refuse a file that is group/world readable
  // or owned by someone else. (The keyring itself is only reachable from the
  // Python package; `tc auth login` users on a keyring should set the env var.)
  const path = tcCliCredentialFile();
  try {
    if (!existsSync(path)) return null;
    const st = statSync(path);
    if ((st.mode & 0o777) !== 0o600) {
      console.error(`threatcluster_mcp: ${path} is not mode 0600; ignoring it`);
      return null;
    }
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
      console.error(`threatcluster_mcp: ${path} is not owned by the current user; ignoring it`);
      return null;
    }
    const v = readFileSync(path, "utf8").trim();
    return v || null;
  } catch {
    return null;
  }
}

export type KeySource = "env" | "tc-cli-env" | "tc-cli-file" | "none";

export function resolveApiKey(): { key: string | null; source: KeySource } {
  const v = (process.env[ENV_API_KEY] || "").trim();
  if (v) return { key: v, source: "env" };
  const t = (process.env[ENV_TC_CLI_TOKEN] || "").trim();
  if (t) return { key: t, source: "tc-cli-env" };
  const f = readTcCliFile();
  if (f) return { key: f, source: "tc-cli-file" };
  return { key: null, source: "none" };
}

export function resolveApiBase(): string {
  return (process.env[ENV_API_BASE] || DEFAULT_API_BASE).trim().replace(/\/+$/, "");
}

export function resolveSite(): string {
  return (process.env[ENV_SITE] || DEFAULT_SITE).trim().replace(/\/+$/, "");
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class ApiError extends Error {
  status: number;
  code: string;
  retryAfter: number | null;
  hint: string | null;
  path: string;
  cost: number;

  constructor(status: number, code: string, message: string,
              opts: { retryAfter?: number | null; hint?: string | null; path?: string; cost?: number } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.cost = opts.cost ?? 0;
    this.code = code;
    this.retryAfter = opts.retryAfter ?? null;
    this.hint = opts.hint ?? null;
    this.path = opts.path ?? "";
  }

  toText(): string {
    const head = this.status ? `ThreatCluster API ${this.status} ${this.code}` : `ThreatCluster API ${this.code}`;
    const parts = [`${head}: ${this.message}`];
    if (this.retryAfter !== null) parts.push(`Retry after ${this.retryAfter} seconds.`);
    if (this.hint) parts.push(this.hint);
    if (this.cost) parts.push(`(cost: ${this.cost} credits)`);
    return parts.join(" ");
  }

  toDict(): Record<string, unknown> {
    const d: Record<string, unknown> = { status: this.status, code: this.code, message: this.message, cost: this.cost };
    if (this.retryAfter !== null) d.retry_after = this.retryAfter;
    if (this.hint) d.hint = this.hint;
    return d;
  }
}

// ---------------------------------------------------------------------------
// Budget bookkeeping (from response headers; no API call needed to read it)
// ---------------------------------------------------------------------------
export class Budget {
  limit: number | null = null;
  remaining: number | null = null;
  resetEpoch: number | null = null;
  creditsBalance: number | null = null;
  sessionCalls = 0;
  sessionCost = 0;
  startedAt = nowIso();
  lastResponseAt: string | null = null;
  lastStatus: number | null = null;
  lastError: Record<string, unknown> | null = null;
  private callTimes: number[] = [];

  static int(v: string | null | undefined): number | null {
    if (v === null || v === undefined) return null;
    const n = parseInt(String(v).trim(), 10);
    return Number.isFinite(n) ? n : null;
  }

  observe(status: number, headers: Headers, cost: number): void {
    this.sessionCalls += 1;
    this.sessionCost += cost;
    const t = Date.now() / 1000;
    this.callTimes = this.callTimes.filter((x) => t - x < 60).concat([t]);
    this.lastResponseAt = nowIso();
    this.lastStatus = status;
    const lim = Budget.int(headers.get("X-RateLimit-Limit"));
    const rem = Budget.int(headers.get("X-RateLimit-Remaining"));
    const rst = Budget.int(headers.get("X-RateLimit-Reset"));
    const bal = Budget.int(headers.get("X-Credits-Balance"));
    if (lim !== null) this.limit = lim;
    if (rem !== null) this.remaining = rem;
    if (rst !== null) this.resetEpoch = rst;
    if (bal !== null) this.creditsBalance = bal;
  }

  requestsLastMinute(): number {
    const t = Date.now() / 1000;
    return this.callTimes.filter((x) => t - x < 60).length;
  }

  brief(): Record<string, unknown> | null {
    if (this.limit === null && this.remaining === null) return null;
    return { remaining: this.remaining, limit: this.limit, resets_at: epochIso(this.resetEpoch) };
  }

  snapshot(): Record<string, unknown> {
    return {
      daily_credits: {
        limit: this.limit,
        remaining: this.remaining,
        resets_at: epochIso(this.resetEpoch),
        pack_balance: this.creditsBalance,
      },
      session: {
        started_at: this.startedAt,
        api_calls: this.sessionCalls,
        credits_spent: this.sessionCost,
        requests_last_minute: this.requestsLastMinute(),
      },
      last_response: { at: this.lastResponseAt, status: this.lastStatus },
      last_error: this.lastError,
    };
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------
export interface ClientOptions {
  base?: string;
  site?: string;
  keySource?: KeySource;
  timeoutMs?: number;
  userAgent?: string;
  fetchImpl?: typeof fetch;
}

export class ThreatClusterClient {
  private readonly secret: string;
  readonly keySource: KeySource;
  readonly base: string;
  readonly site: string;
  readonly timeoutMs: number;
  readonly userAgent: string;
  readonly budget = new Budget();
  private readonly fetchImpl: typeof fetch;

  constructor(apiKey: string | null, opts: ClientOptions = {}) {
    this.secret = apiKey || "";
    this.keySource = opts.keySource ?? "none";
    this.base = (opts.base ?? resolveApiBase()).replace(/\/+$/, "");
    this.site = (opts.site ?? resolveSite()).replace(/\/+$/, "");
    this.timeoutMs = opts.timeoutMs ?? REQUEST_TIMEOUT_MS;
    this.userAgent = opts.userAgent ?? "threatcluster-mcp (node)";
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  get hasKey(): boolean {
    return this.secret.length > 0;
  }

  redact(text: unknown): string {
    let s = text === null || text === undefined ? "" : String(text);
    if (this.secret && this.secret.length >= 8) s = s.split(this.secret).join("[redacted]");
    return s;
  }

  private authHeaders(): Record<string, string> {
    if (!this.secret) return {};
    // tc_live_* / tc_agent_* are API keys (X-API-Key). Anything else is a
    // short-lived bearer JWT, e.g. one minted by `tc login`.
    if (this.secret.startsWith("tc_")) return { "X-API-Key": this.secret };
    return { Authorization: "Bearer " + this.secret };
  }

  /** GET `path` (relative to the API base). Returns `[json, cost]`. Throws
   *  ApiError for any non-2xx status, network failure or non-JSON body.
   *  null / undefined / "" params are dropped. */
  async get(path: string, params: Record<string, unknown> = {}): Promise<[Json, number]> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v === null || v === undefined || v === "") continue;
      qs.set(k, String(v));
    }
    const q = qs.toString();
    const url = this.base + path + (q ? "?" + q : "");
    let resp: Response;
    try {
      resp = await this.fetchImpl(url, {
        method: "GET",
        headers: { "User-Agent": this.userAgent, Accept: "application/json", ...this.authHeaders() },
        redirect: "manual",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e: any) {
      const isTimeout = e && (e.name === "TimeoutError" || e.name === "AbortError");
      const err = isTimeout
        ? new ApiError(0, "timeout", `no response from ${this.base} within ${Math.round(this.timeoutMs / 1000)}s`, { path })
        : new ApiError(0, "network_error", this.redact(`${e?.name || "Error"}: ${e?.message || e}`),
                       { path, hint: `Check ${ENV_API_BASE} (currently ${this.base}).` });
      this.budget.lastError = err.toDict();
      throw err;
    }
    const cost = Budget.int(resp.headers.get("X-Request-Cost")) ?? 0;
    this.budget.observe(resp.status, resp.headers, cost);
    const text = await resp.text();
    let body: Json = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
    if (resp.status >= 400) {
      const err = this.errorFrom(resp.status, resp.headers, body, text, path);
      err.cost = cost;
      this.budget.lastError = err.toDict();
      throw err;
    }
    if (body === null) {
      const err = new ApiError(resp.status, "bad_response", "the API returned a non-JSON body", { path });
      this.budget.lastError = err.toDict();
      throw err;
    }
    this.budget.lastError = null;
    return [body, cost];
  }

  private errorFrom(status: number, headers: Headers, body: Json, text: string, path: string): ApiError {
    let code = "";
    let message = "";
    const detail = body && typeof body === "object" ? body.detail : undefined;
    if (detail && typeof detail === "object") {
      code = String(detail.error || "");
      message = String(detail.message || "");
    } else if (typeof detail === "string") {
      message = detail;
    }
    if (body && typeof body === "object") {
      if (!code && typeof body.error === "string") code = body.error;
      if (!message && typeof body.message === "string") message = body.message;
    }
    if (!message) message = (text || "").trim().slice(0, 300) || "no error body";
    let retryAfter = Budget.int(headers.get("Retry-After"));
    if (retryAfter === null && detail && typeof detail === "object") retryAfter = Budget.int(detail.retry_after);
    let hint: string | null = null;
    if (status === 401) {
      code = code || "unauthorized";
      hint = `Set ${ENV_API_KEY} to a ThreatCluster API key (tc_live_... or tc_agent_...). Free keys: ${FREE_KEY_URL}`;
    } else if (status === 403) {
      if (code === "insufficient_scope" && detail && typeof detail === "object") {
        const granted: string[] = Array.isArray(detail.granted_scopes) ? detail.granted_scopes : [];
        hint = `This key lacks the '${detail.required_scope}' scope (granted: ${granted.join(", ") || "none"}). ` +
          `Free keys carry the five read scopes; MSSP scopes need a Business or MSSP plan: ${PRICING_URL}`;
      } else if (code === "lookback_exceeded") {
        const days = detail && typeof detail === "object" && detail.lookback_days ? detail.lookback_days : 7;
        hint = `Free keys see the last ${days} days; Researcher and above have no lookback limit: ${PRICING_URL}`;
      } else {
        code = code || "forbidden";
      }
    } else if (status === 404) {
      code = "not_found";
      message = `nothing matches ${path}`;
    } else if (status === 429) {
      code = code || "rate_limited";
      if (retryAfter === null) retryAfter = 60;
      hint = code === "daily_budget_exceeded"
        ? `The daily budget refills at 00:00 UTC. Credit packs and paid plans lift it: ${PRICING_URL}`
        : "Space calls out; free keys get 30 requests a minute.";
    } else if (status >= 500) {
      code = code || "server_error";
      hint = "Temporary; retry once after a few seconds.";
    }
    code = code || `http_${status}`;
    return new ApiError(status, this.redact(code), this.redact(message), { retryAfter, hint, path });
  }
}

const SECRET_LIKE = /(tc_(?:live|agent)_[A-Za-z0-9_\-]{6,})/g;

/** Belt and braces: mask anything shaped like a ThreatCluster key even if it
 *  is not the configured one (e.g. a key pasted into a tool argument). */
export function scrubKeyShapes(text: string): string {
  return text.replace(SECRET_LIKE, "tc_[redacted]");
}
