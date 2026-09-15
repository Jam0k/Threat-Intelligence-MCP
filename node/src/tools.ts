/**
 * Tool spec loading, argument validation and result shaping.
 *
 * tools.json is the single source of truth shared with the PyPI package.
 * The shaping here mirrors python/src/threatcluster_mcp/tools.py line for
 * line; the replay tests assert both produce the same JSON for the same
 * recorded API responses.
 */
import { readFileSync } from "node:fs";
import { z } from "zod";
import { ThreatClusterClient, nowIso, type Json } from "./client.js";

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------
const PropertySchema: z.ZodType<any> = z.lazy(() => z.object({
  type: z.enum(["string", "integer", "boolean", "array", "number"]),
  description: z.string().optional(),
  enum: z.array(z.string()).optional(),
  default: z.any().optional(),
  minimum: z.number().optional(),
  maximum: z.number().optional(),
  minLength: z.number().optional(),
  maxLength: z.number().optional(),
  maxItems: z.number().optional(),
  pattern: z.string().optional(),
  items: PropertySchema.optional(),
}).strict());

const InputSchema = z.object({
  type: z.literal("object"),
  properties: z.record(z.string(), PropertySchema),
  required: z.array(z.string()),
  additionalProperties: z.literal(false),
}).strict();

const ToolSchema = z.object({
  name: z.string().regex(/^[a-z_]+$/),
  title: z.string(),
  description: z.string().min(20),
  inputSchema: InputSchema,
  endpoints: z.array(z.string()),
  credits: z.string(),
  credits_max: z.number().int().nonnegative(),
}).strict();

const PromptSchema = z.object({
  name: z.string(),
  title: z.string(),
  description: z.string(),
  arguments: z.array(z.object({ name: z.string(), description: z.string().optional(), required: z.boolean().optional() }).strict()),
  template: z.string(),
}).strict();

export const SpecSchema = z.object({
  spec_version: z.number().int(),
  server: z.object({
    name: z.string(),
    title: z.string(),
    api_base: z.string().url(),
    site: z.string().url(),
    free_key_url: z.string().url(),
    env: z.record(z.string(), z.string()),
    instructions: z.string(),
  }).strict(),
  tools: z.array(ToolSchema).min(1),
  prompts: z.array(PromptSchema),
}).strict();

export type Spec = z.infer<typeof SpecSchema>;
export type ToolSpec = z.infer<typeof ToolSchema>;
export type PromptSpec = z.infer<typeof PromptSchema>;
export type PropertySpec = z.infer<typeof PropertySchema>;

let SPEC: Spec | null = null;

export function loadSpec(): Spec {
  if (SPEC === null) {
    const raw = readFileSync(new URL("../tools.json", import.meta.url), "utf8");
    SPEC = SpecSchema.parse(JSON.parse(raw));
  }
  return SPEC;
}

export function toolSpecs(): ToolSpec[] {
  return loadSpec().tools;
}

export function toolSpec(name: string): ToolSpec | undefined {
  return loadSpec().tools.find((t) => t.name === name);
}

export function promptSpecs(): PromptSpec[] {
  return loadSpec().prompts;
}

// ---------------------------------------------------------------------------
// Argument validation (same messages as the Python package)
// ---------------------------------------------------------------------------
export class ToolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ToolInputError";
  }
}

function check(name: string, ps: PropertySpec, v: unknown): unknown {
  const t = ps.type;
  if (t === "string") {
    if (typeof v !== "string") throw new ToolInputError(`argument '${name}' must be a string`);
    if (ps.enum && !ps.enum.includes(v)) throw new ToolInputError(`argument '${name}' must be one of: ${ps.enum.join(", ")}`);
    const lo = ps.minLength, hi = ps.maxLength;
    const len = Array.from(v).length;
    if ((lo !== undefined && len < lo) || (hi !== undefined && len > hi)) {
      throw new ToolInputError(`argument '${name}' must be between ${lo || 0} and ${hi !== undefined ? hi : "unlimited"} characters`);
    }
    if (ps.pattern && !new RegExp(ps.pattern).test(v)) {
      throw new ToolInputError(`argument '${name}' does not match the expected format (${ps.description || ps.pattern})`);
    }
    return v;
  }
  if (t === "integer") {
    if (typeof v !== "number" || !Number.isInteger(v)) throw new ToolInputError(`argument '${name}' must be an integer`);
    const lo = ps.minimum, hi = ps.maximum;
    if ((lo !== undefined && v < lo) || (hi !== undefined && v > hi)) {
      throw new ToolInputError(`argument '${name}' must be an integer between ${lo} and ${hi}`);
    }
    return v;
  }
  if (t === "boolean") {
    if (typeof v !== "boolean") throw new ToolInputError(`argument '${name}' must be true or false`);
    return v;
  }
  if (t === "array") {
    if (!Array.isArray(v)) throw new ToolInputError(`argument '${name}' must be a list`);
    if (ps.maxItems !== undefined && v.length > ps.maxItems) {
      throw new ToolInputError(`argument '${name}' must be a list of at most ${ps.maxItems} items`);
    }
    return ps.items ? v.map((x, i) => check(`${name}[${i}]`, ps.items, x)) : v.slice();
  }
  return v;
}

export function validateArgs(schema: ToolSpec["inputSchema"], args: unknown): Record<string, unknown> {
  if (args === null || args === undefined) args = {};
  if (typeof args !== "object" || Array.isArray(args)) throw new ToolInputError("arguments must be an object");
  const a = args as Record<string, unknown>;
  const props = schema.properties;
  for (const k of Object.keys(a)) {
    if (!(k in props)) throw new ToolInputError(`unknown argument '${k}'`);
  }
  for (const k of schema.required) {
    if (a[k] === null || a[k] === undefined) throw new ToolInputError(`missing required argument '${k}'`);
  }
  const out: Record<string, unknown> = {};
  for (const [k, ps] of Object.entries(props)) {
    if (k in a && a[k] !== null && a[k] !== undefined) out[k] = check(k, ps, a[k]);
    else if (ps.default !== undefined) out[k] = ps.default;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Shaping helpers (mirrored from tools.py)
// ---------------------------------------------------------------------------
const STOP_WORDS = new Set(["the", "a", "an", "of", "in", "on", "for", "to", "and", "or", "with", "by", "from", "at", "is",
  "are", "was", "were", "be", "about", "into", "recent", "recently", "latest", "new", "attack", "attacks", "incident",
  "incidents", "threat", "threats"]);
const WORD_RE = /[A-Za-z0-9][A-Za-z0-9.\-]+/g;
const PRIMARY_ENTITY_TYPES = ["apt_group", "ransomware_group", "malware", "tool", "campaign", "cve", "company", "platform",
  "country", "industry", "attack_type", "mitre_attack"];
const INDICATOR_TYPES = new Set(["ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "btc", "eth", "xmr"]);
const MAX_SEARCH_CALLS = 8;
const TIME_FILTER_DAYS: Record<string, number> = { "24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90 };
/** A stage is good enough to stop laddering at this many hits. */
const ENOUGH_HITS = 3;
/** Words fanned out per search_everything call; caps the credit cost. */
const MAX_SEARCH_WORDS = 4;
const IOC_KEYS = ["type", "ioc_type", "value", "confidence", "reason", "context", "first_seen", "last_seen", "source", "tags"];

const g = (o: any, k: string): any => (o && typeof o === "object" && o[k] !== undefined ? o[k] : null);

export function trunc(s: unknown, n: number): string | null {
  if (s === null || s === undefined) return null;
  const str = String(s);
  const cps = Array.from(str);
  return cps.length <= n ? str : cps.slice(0, n).join("").trimEnd() + "…";
}

export function dateOnly(v: unknown): string | null {
  if (v === null || v === undefined || v === "") return null;
  return String(v).slice(0, 10);
}

export function shortId(clusterId: unknown): string {
  return String(clusterId || "").replace(/-/g, "").slice(-8);
}

export function wordsOf(query: string): string[] {
  return (query.match(WORD_RE) || []).filter((w) => !STOP_WORDS.has(w.toLowerCase()));
}

/** Map a day count onto the nearest backend time_filter that is >= it.
 *
 * Previously anything over 7 became "30d", so days=90 searched 30 days and
 * reported window_searched="30d" with no indication the request had been
 * narrowed. The backend allowlists 14d/30d/90d and applies its own per-tier
 * clamp, so send the real window and let the server decide. */
export function daysToTimeFilter(days: number | null | undefined): string {
  if (days === null || days === undefined) return "7d";
  if (days <= 1) return "24h";
  if (days <= 7) return "7d";
  if (days <= 14) return "14d";
  if (days <= 30) return "30d";
  return "90d";
}

/** Python's urllib.parse.quote(value, safe='') — encodes !'()* too. */
export function pyQuote(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

export function normaliseEntities(ents: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (ents && typeof ents === "object" && !Array.isArray(ents)) {
    for (const [t, vals] of Object.entries(ents as Record<string, unknown>)) {
      if (!Array.isArray(vals)) continue;
      out[t] = vals.map((v) => (v && typeof v === "object" ? String((v as any).value || (v as any).entity_value || "") : String(v)));
    }
  } else if (Array.isArray(ents)) {
    for (const row of ents) {
      if (row && typeof row === "object" && (row as any).entity_type) {
        const t = String((row as any).entity_type);
        (out[t] ||= []).push(String((row as any).entity_value || (row as any).value || ""));
      }
    }
  }
  const cleaned: Record<string, string[]> = {};
  for (const [t, vals] of Object.entries(out)) {
    const kept = vals.filter((v) => v);
    if (kept.length) cleaned[t] = kept;
  }
  return cleaned;
}

function pickTypes(ents: Record<string, string[]>, n: number): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const t of PRIMARY_ENTITY_TYPES) if (ents[t] && ents[t].length) out[t] = ents[t].slice(0, n);
  return out;
}

export class Shaper {
  readonly site: string;
  constructor(site: string) {
    this.site = site.replace(/\/+$/, "");
  }

  clusterUrl(c: any): string {
    const ident = g(c, "slug") || g(c, "short_id") || shortId(g(c, "cluster_id"));
    return `${this.site}/cluster/${ident}`;
  }
  entityUrl(etype: string, value: string): string {
    return `${this.site}/entities/${String(etype).replace(/_/g, "-")}/${pyQuote(String(value))}`;
  }
  groupUrl(group: string): string {
    return `${this.site}/dark-web/group/${pyQuote(String(group))}`;
  }
  victimUrl(v: any): string {
    if (g(v, "id")) return `${this.site}/dark-web/victim/${pyQuote(String(v.id))}`;
    return this.groupUrl(String(g(v, "group") || ""));
  }
  cveUrl(cveId: string): string {
    return `${this.site}/entities/cve/${pyQuote(String(cveId).toUpperCase())}`;
  }

  cluster(c: any, summaryChars = 350): Record<string, unknown> {
    const ents = normaliseEntities(g(c, "entities"));
    return {
      cluster_id: g(c, "cluster_id"),
      short_id: g(c, "short_id") || shortId(g(c, "cluster_id")),
      title: g(c, "ai_title") || g(c, "title"),
      date: dateOnly(g(c, "date_range_latest") || g(c, "updated_at") || g(c, "created_at")),
      threat_score: g(c, "threat_score"),
      urgency: g(c, "urgency_level"),
      article_count: g(c, "article_count"),
      summary: trunc(g(c, "ai_summary"), summaryChars),
      sources: (Array.isArray(c.sources) ? c.sources : []).slice(0, 5),
      entities: pickTypes(ents, 6),
      url: this.clusterUrl(c),
    };
  }

  clusterBrief(c: any): Record<string, unknown> {
    return {
      cluster_id: g(c, "cluster_id"),
      title: g(c, "ai_title") || g(c, "title"),
      date: dateOnly(g(c, "date_range_latest") || g(c, "updated_at") || g(c, "created_at")),
      threat_score: g(c, "threat_score"),
      url: this.clusterUrl(c),
    };
  }

  clusterDetail(c: any): Record<string, unknown> {
    const ents = normaliseEntities(g(c, "entities"));
    const timeline: any[] = (Array.isArray(c.timeline) ? c.timeline : []).filter((e: any) => e && typeof e === "object");
    const articles: any[] = (Array.isArray(c.articles) ? c.articles : []).filter((a: any) => a && typeof a === "object" && !a.is_reference_only);
    const out: Record<string, unknown> = {
      cluster_id: g(c, "cluster_id"),
      short_id: g(c, "short_id") || shortId(g(c, "cluster_id")),
      title: g(c, "ai_title") || g(c, "title"),
      date: dateOnly(g(c, "date_range_latest") || g(c, "updated_at") || g(c, "created_at")),
      first_seen: dateOnly(g(c, "date_range_earliest") || g(c, "created_at")),
      threat_score: g(c, "threat_score"),
      urgency: g(c, "urgency_level"),
      article_count: g(c, "article_count"),
      summary: trunc(g(c, "ai_summary"), 1500),
      analysis: g(c, "enhanced_summary") ? trunc(c.enhanced_summary, 1200) : null,
      keywords: (Array.isArray(c.keywords) ? c.keywords : []).slice(0, 10),
      sources: (Array.isArray(c.sources) ? c.sources : []).slice(0, 10),
      timeline: timeline.slice(0, 8).map((e) => ({
        date: dateOnly(g(e, "date")),
        event: trunc(g(e, "event") || g(e, "description"), 200),
        detail: trunc(g(e, "detail"), 240),
        source: g(e, "source"),
        source_url: g(e, "source_url"),
      })),
      timeline_truncated: Boolean(g(c, "timeline_truncated")) || timeline.length > 8,
      entities: Object.fromEntries(Object.entries(ents).map(([t, vals]) => [t, vals.slice(0, 10)])),
      articles: articles.slice(0, 8).map((a) => ({
        date: dateOnly(g(a, "pub_date")),
        source: g(a, "source"),
        title: g(a, "title"),
        url: g(a, "url"),
      })),
      url: this.clusterUrl(c),
      tier: g(c, "tier"),
    };
    if (out.analysis === null) delete out.analysis;
    return out;
  }

  cve(c: any, full: boolean): Record<string, unknown> {
    const cvss: Record<string, unknown> = { score: g(c, "cvss_v3_score"), severity: g(c, "cvss_v3_severity") };
    const out: Record<string, unknown> = {
      cve_id: g(c, "cve_id"),
      description: trunc(g(c, "description"), full ? 600 : 240),
      cvss,
      epss: { score: g(c, "epss_score"), percentile: g(c, "epss_percentile") },
      in_kev: g(c, "in_kev"),
      kev_added_date: g(c, "kev_added_date"),
      kev_due_date: g(c, "kev_due_date"),
      ransomware_use: g(c, "ransomware_use"),
      has_exploit: g(c, "has_exploit"),
      exploit_count: g(c, "exploit_count"),
      vendors: (Array.isArray(c.affected_vendors) ? c.affected_vendors : []).slice(0, 10),
      products: (Array.isArray(c.affected_products) ? c.affected_products : []).slice(0, 10),
      published: dateOnly(g(c, "published_date")),
      last_modified: dateOnly(g(c, "last_modified")),
      url: this.cveUrl(String(g(c, "cve_id") || "")),
    };
    if (full) {
      cvss.vector = g(c, "cvss_v3_vector");
      out.cwe_ids = Array.isArray(c.cwe_ids) ? c.cwe_ids.slice() : [];
      out.exploit_urls = (Array.isArray(c.exploit_urls) ? c.exploit_urls : []).slice(0, 5);
      const refs: any[] = Array.isArray(c.reference_urls) ? c.reference_urls : [];
      out.references = refs.map((r) => (r && typeof r === "object" ? g(r, "url") : String(r))).slice(0, 5);
    }
    return out;
  }

  victim(v: any): Record<string, unknown> {
    return {
      date: dateOnly(g(v, "discovered")),
      group: g(v, "group") || g(v, "group_name"),
      victim: g(v, "name") || g(v, "victim_name"),
      sector: g(v, "sector"),
      country: g(v, "country"),
      website: g(v, "website"),
      url: this.victimUrl(v),
    };
  }
}

function compactIoc(row: any): any {
  if (!row || typeof row !== "object") return row;
  const picked: Record<string, unknown> = {};
  for (const k of IOC_KEYS) if (k in row) picked[k] = row[k];
  return Object.keys(picked).length ? picked : row;
}

const arr = (v: unknown): any[] => (Array.isArray(v) ? v : []);
const isObj = (v: unknown): v is Record<string, any> => !!v && typeof v === "object" && !Array.isArray(v);

// ---------------------------------------------------------------------------
// Runner: one method per tool
// ---------------------------------------------------------------------------
type ToolResult = [Record<string, unknown>, number];

export class ToolRunner {
  readonly shape: Shaper;
  constructor(readonly client: ThreatClusterClient) {
    this.shape = new Shaper(client.site);
  }

  async run(name: string, args: Record<string, any>): Promise<Record<string, unknown>> {
    const fn = (this as any)[`tool_${name}`];
    if (typeof fn !== "function") throw new ToolInputError(`unknown tool '${name}'`);
    const [data, cost] = (await fn.call(this, args)) as ToolResult;
    return { tool: name, as_of: nowIso(), cost, budget: this.client.budget.brief(), ...data };
  }

  async tool_search_threats(a: { query: string; alternatives?: string[]; days?: number; limit: number }): Promise<ToolResult> {
    const query = a.query.trim();
    const alts = (a.alternatives || []).map((x) => x.trim()).filter((x) => x);
    const words = wordsOf(query);
    const days = a.days ?? null;
    const initialTf = daysToTimeFilter(days);
    const stages: Array<[string, string[], boolean]> = [["phrase", [query, ...alts], false]];
    if (words.length >= 2) stages.push(["words", words.slice(0, 4), true]);
    let calls = 0, cost = 0;
    const termsSearched: string[] = [];
    let found: any[] = [];
    let matchedStage: string | null = null;
    let windowUsed = initialTf;
    let widened = false;
    let lookbackDays: number | null = null;

    const fetchTerm = async (term: string, tf: string): Promise<any[]> => {
      calls += 1;
      termsSearched.push(term);
      const [body, c] = await this.client.get("/threats", { keyword: term, limit: 25, time_filter: tf });
      cost += c;
      if (isObj(body) && body.time_filter) windowUsed = String(body.time_filter);
      if (isObj(body) && Number.isInteger(body.lookback_days)) lookbackDays = body.lookback_days;
      return arr(body?.threats).filter((r) => isObj(r) && r.cluster_id);
    };
    const dedupe = (rows: any[]): any[] => {
      const seen = new Set<string>();
      const out: any[] = [];
      for (const r of rows) {
        const cid = String(r.cluster_id);
        if (!seen.has(cid)) { seen.add(cid); out.push(r); }
      }
      return out;
    };

    const windows = [initialTf, ...["30d", "90d"].filter(
      (w) => (TIME_FILTER_DAYS[w] ?? 0) > (TIME_FILTER_DAYS[initialTf] ?? 0))];
    for (let wi = 0; wi < windows.length; wi++) {
      const tf = windows[wi];
      const foundBefore = found.length;
      for (const [, terms, isWords] of stages) {
        if (calls >= MAX_SEARCH_CALLS) break;
        const perTerm: any[][] = [];
        for (const term of terms) {
          if (calls >= MAX_SEARCH_CALLS) break;
          perTerm.push(await fetchTerm(term, tf));
        }
        if (!perTerm.length) continue;
        if (isWords) {
          const ids = perTerm.map((rows) => new Set(rows.map((r) => String(r.cluster_id))));
          const common = ids.length ? [...ids[0]].filter((id) => ids.every((s) => s.has(id))) : [];
          const commonSet = new Set(common);
          const allWords = dedupe(perTerm.flat().filter((r) => commonSet.has(String(r.cluster_id))));
          if (allWords.length > found.length) { found = allWords; matchedStage = "all words"; }
          if (found.length >= 3) break;
          const anyWord = dedupe(perTerm.flat());
          if (anyWord.length > found.length) { found = anyWord; matchedStage = "any word"; }
        } else {
          const rows = dedupe(perTerm.flat());
          if (rows.length > found.length) { found = rows; matchedStage = "phrase"; }
        }
        if (found.length >= 3) break;
      }
      if (wi > 0 && found.length > foundBefore) widened = true;
      if (found.length >= 3 || calls >= MAX_SEARCH_CALLS) break;
      if (lookbackDays !== null && lookbackDays <= (TIME_FILTER_DAYS[tf] ?? 7)) break;
    }
    found.sort((x, y) => (y.threat_score || 0) - (x.threat_score || 0));
    return [{
      query,
      alternatives: alts,
      days,
      window_searched: windowUsed,
      widened_beyond_days: widened,
      matched_stage: found.length ? matchedStage : null,
      terms_searched: termsSearched,
      api_calls: calls,
      count: Math.min(found.length, a.limit),
      clusters: found.slice(0, a.limit).map((c) => this.shape.cluster(c)),
    }, cost];
  }

  /** Unified search with the same fallback ladder as search_threats.
   *
   * GET /search is a literal substring match, so a descriptive query
   * ("Qilin ransomware group") matched nothing while its head word ("Qilin")
   * matched 24 hits — and the empty result was indistinguishable from an
   * empty corpus. Retry with progressively looser terms and report which
   * stage matched. */
  async tool_search_everything(a: { query: string; days?: number; limit: number }): Promise<ToolResult> {
    const q0 = a.query.trim();
    const qWords = wordsOf(q0).slice(0, MAX_SEARCH_WORDS);
    const BUCKETS = ["clusters", "entities", "darkweb"] as const;
    const keyOf = (bucket: string, r: Record<string, unknown>): string => {
      if (bucket === "clusters") return String(g(r, "cluster_id") ?? g(r, "short_id") ?? JSON.stringify(r));
      if (bucket === "entities") return `${g(r, "entity_type")}\u241f${g(r, "entity_value")}`;
      return String(g(r, "url") ?? `${g(r, "type")}\u241f${g(r, "name")}`);
    };
    const merge = (bodies: Record<string, unknown>[], commonOnly: boolean): Record<string, unknown> => {
      const out: Record<string, unknown> = {};
      for (const bucket of BUCKETS) {
        const perWord = bodies.map((b) => {
          const m = new Map<string, Record<string, unknown>>();
          for (const r of arr(b[bucket])) if (isObj(r)) m.set(keyOf(bucket, r as Record<string, unknown>), r as Record<string, unknown>);
          return m;
        }).filter((m) => (commonOnly ? m.size > 0 : true));
        if (!perWord.length) { out[bucket] = []; continue; }
        let keys = new Set(perWord[0]!.keys());
        for (const m of perWord.slice(1)) {
          keys = commonOnly
            ? new Set([...keys].filter((k) => m.has(k)))
            : new Set([...keys, ...m.keys()]);
        }
        const seen = new Set<string>(); const rows: Record<string, unknown>[] = [];
        for (const m of perWord) for (const [k, r] of m) if (keys.has(k) && !seen.has(k)) { seen.add(k); rows.push(r); }
        out[bucket] = rows;
      }
      for (const meta of ["days", "lookback_days", "total"]) {
        const hit = bodies.find((b) => b[meta] !== undefined && b[meta] !== null);
        if (hit) out[meta] = hit[meta];
      }
      return out;
    };
    const size = (b: Record<string, unknown>) => BUCKETS.reduce((n, k) => n + arr(b[k]).length, 0);

    let body: Record<string, unknown> = {};
    let cost = 0;
    let matched_stage: string | null = null;
    let best = -1;

    // Stage 1: the phrase exactly as asked.
    {
      const [b, c] = await this.client.get("/search", { q: q0, limit: a.limit, days: a.days ?? null });
      cost += c;
      body = isObj(b) ? (b as Record<string, unknown>) : {};
      matched_stage = "phrase"; best = size(body);
    }
    // Stages 2 and 3 fan out ONE CALL PER WORD, the way search_threats does.
    // Joining the words back into a string only re-ran the phrase (GET /search
    // is a substring match), and picking the longest word chose "ransomware"
    // over "Qilin" — 2,250 generic clusters instead of the 135 that matter.
    if (best < ENOUGH_HITS && qWords.length >= 2) {
      const per: Record<string, unknown>[] = [];
      for (const w of qWords) {
        if (w.length < 2) continue;
        const [wb, wc] = await this.client.get("/search", { q: w, limit: a.limit, days: a.days ?? null });
        cost += wc;
        per.push(isObj(wb) ? (wb as Record<string, unknown>) : {});
      }
      if (per.length) {
        const both = merge(per, true);
        if (size(both) > best) { body = both; matched_stage = "all words"; best = size(both); }
        if (best < ENOUGH_HITS) {
          const either = merge(per, false);
          if (size(either) > best) { body = either; matched_stage = "any word"; best = size(either); }
        }
      }
    }
    const entities = arr(body.entities).slice(0, a.limit).filter(isObj).map((e) => ({
      type: g(e, "entity_type"),
      value: g(e, "entity_value"),
      cluster_count: g(e, "cluster_count"),
      article_count: g(e, "article_count"),
      url: this.shape.entityUrl(String(g(e, "entity_type") || ""), String(g(e, "entity_value") || "")),
    }));
    const darkweb: Record<string, unknown>[] = [];
    for (const d of arr(body.darkweb).slice(0, a.limit)) {
      if (!isObj(d)) continue;
      const kind = g(d, "type");
      const url = kind === "victim" ? this.shape.victimUrl(d)
        : kind === "group" ? this.shape.groupUrl(String(g(d, "name") || ""))
        : `${this.shape.site}/dark-web`;
      darkweb.push({ type: kind, name: g(d, "name"), date: dateOnly(g(d, "date")), group: g(d, "group"),
        country: g(d, "country"), sector: g(d, "sector"), url });
    }
    return [{
      query: q0,
      matched_stage,
      days: g(body, "days") || g(body, "lookback_days"),
      total: g(body, "total"),
      clusters: arr(body.clusters).slice(0, a.limit).filter(isObj).map((c) => this.shape.cluster(c)),
      entities,
      darkweb,
    }, cost];
  }

  async tool_newest_threats(a: { time_filter: string; limit: number; sort_by: string }): Promise<ToolResult> {
    const [body, cost] = await this.client.get("/threats", { time_filter: a.time_filter, limit: a.limit, sort_by: a.sort_by });
    const threats = arr(body.threats);
    return [{
      time_filter: g(body, "time_filter") || a.time_filter,
      sort_by: a.sort_by,
      count: threats.length,
      clusters: threats.slice(0, a.limit).filter(isObj).map((c) => this.shape.cluster(c, 300)),
    }, cost];
  }

  async tool_get_threat(a: { identifier: string; include_iocs: boolean }): Promise<ToolResult> {
    const ident = a.identifier.trim();
    let [body, cost] = await this.client.get(`/threats/${pyQuote(ident)}`);
    const out = this.shape.clusterDetail(body);
    if (a.include_iocs) {
      const cid = String(g(body, "cluster_id") || ident);
      const [iocs, c2] = await this.client.get(`/threats/${pyQuote(cid)}/iocs`, { format: "json" });
      cost += c2;
      let rows: any[] | null = isObj(iocs) ? (iocs.iocs ?? null) : null;
      if (rows === null && Array.isArray(iocs)) rows = iocs;
      rows = rows || [];
      out.iocs = { count: isObj(iocs) && iocs.count !== undefined ? iocs.count : rows.length,
        indicators: rows.slice(0, 50).map(compactIoc) };
    }
    return [out, cost];
  }

  async tool_leak_site_victims(a: { days: number; sector?: string; group?: string; country?: string; victim?: string; limit: number }): Promise<ToolResult> {
    const country = a.country ? a.country.toUpperCase() : null;
    const params = { days: a.days, limit: a.victim ? 100 : a.limit, group: a.group ?? null, country, sector: a.sector ?? null };
    let [body, cost] = await this.client.get("/darkweb/ransomware/victims", params);
    let rows = arr(body.victims).filter(isObj);
    if (a.victim) {
      const needle = a.victim.toLowerCase();
      rows = rows.filter((v) => `${g(v, "name") || ""} ${g(v, "website") || ""}`.toLowerCase().includes(needle));
    }
    const [facets, c2] = await this.client.get("/darkweb/ransomware/victims/facets", { days: a.days });
    cost += c2;
    const tally = (key: string, n: number) => arr(facets[key]).slice(0, n).filter(isObj).map((f) => ({ value: g(f, "value"), count: g(f, "count") }));
    const byGroup = tally("groups", 12).map((f) => ({ group: f.value, count: f.count, url: this.shape.groupUrl(String(f.value)) }));
    const windowTotal = arr(facets.groups).filter(isObj).reduce((s, f) => s + (parseInt(String(g(f, "count") || 0), 10) || 0), 0);
    const filters: Record<string, unknown> = {};
    for (const [k, v] of Object.entries({ sector: a.sector, group: a.group, country, victim: a.victim })) if (v) filters[k] = v;
    const lb = g(body, "lookback_days");
    return [{
      days: lb && Number(lb) < a.days ? lb : a.days,
      filters,
      window_total_listings: windowTotal,
      by_group: byGroup,
      by_sector: tally("sectors", 10),
      by_country: tally("countries", 8),
      listings_count: Math.min(rows.length, a.limit),
      listings: rows.slice(0, a.limit).map((v) => this.shape.victim(v)),
      note: "Listings are claims by the groups, not confirmed breaches. The tally covers every listing in the window " +
        "(all groups, sectors and countries); the listings are the newest that match the filters.",
    }, cost];
  }

  async tool_lookup_entity(a: { name: string; entity_type?: string }): Promise<ToolResult> {
    const name = a.name.trim();
    const entityType = a.entity_type ?? null;
    let [body, cost] = await this.client.get("/entities/search", { q: name, entity_type: entityType, limit: 5 });
    const hits = arr(body.entities).filter((h) => isObj(h) && h.entity_value);
    if (!hits.length) {
      return [{ found: false, name, entity_type: entityType,
        message: `no entity in the corpus matches '${name}'` + (entityType ? ` of type ${entityType}` : "") }, cost];
    }
    const top = hits[0];
    const etype = String(g(top, "entity_type") || entityType || "");
    const evalue = String(top.entity_value);
    const [detail, c2] = await this.client.get(`/entities/${pyQuote(etype)}/${pyQuote(evalue)}`);
    cost += c2;
    const ent = isObj(detail.entity) ? detail.entity : {};
    const co = normaliseEntities(g(detail, "co_entities"));
    return [{
      found: true,
      entity: {
        type: etype,
        value: g(ent, "entity_value") || evalue,
        mentions: g(ent, "frequency") !== null ? g(ent, "frequency") : g(top, "article_count"),
        cluster_count: g(top, "cluster_count"),
        article_count: g(top, "article_count"),
        first_seen: dateOnly(g(ent, "first_seen")),
        last_seen: dateOnly(g(ent, "last_seen")),
        url: this.shape.entityUrl(etype, g(ent, "entity_value") || evalue),
      },
      aliases: arr(detail.aliases).slice(0, 10),
      recent_clusters: arr(detail.clusters).slice(0, 5).filter(isObj).map((c) => this.shape.clusterBrief(c)),
      recent_articles: arr(detail.articles).slice(0, 5).filter(isObj).map((x) => ({
        date: dateOnly(g(x, "pub_date")), source: g(x, "source"), title: g(x, "title"), url: g(x, "url") })),
      related: pickTypes(co, 6),
      totals: { clusters: g(detail, "clusters_total"), articles: g(detail, "articles_total") },
      other_matches: hits.slice(1, 4).map((h) => ({ value: g(h, "entity_value"), type: g(h, "entity_type") })),
      lookback_days: g(detail, "lookback_days"),
    }, cost];
  }

  async tool_get_vulnerability(a: { cve_id: string }): Promise<ToolResult> {
    const cve = a.cve_id.trim().toUpperCase();
    const [body, cost] = await this.client.get(`/vulnerabilities/${pyQuote(cve)}`);
    return [this.shape.cve(body, true), cost];
  }

  async tool_exploited_vulnerabilities(a: { days: number; kev_only: boolean; has_exploit: boolean; severity?: string; vendor?: string; product?: string; limit: number }): Promise<ToolResult> {
    const params = { days: a.days, kev_only: a.kev_only ? "true" : "false", has_exploit: a.has_exploit ? "true" : "false",
      severity: a.severity ?? null, vendor: a.vendor ?? null, product: a.product ?? null, limit: a.limit };
    const [body, cost] = await this.client.get("/vulnerabilities", params);
    const filters: Record<string, unknown> = {};
    for (const [k, v] of Object.entries({ kev_only: a.kev_only, has_exploit: a.has_exploit, severity: a.severity, vendor: a.vendor, product: a.product })) if (v) filters[k] = v;
    const cves = arr(body.cves);
    return [{
      days: g(body, "days") || a.days,
      filters,
      total: g(body, "total"),
      count: cves.length,
      cves: cves.slice(0, a.limit).filter(isObj).map((c) => this.shape.cve(c, false)),
    }, cost];
  }

  async tool_trending_entities(a: { time_filter: string; entity_types?: string[]; limit: number }): Promise<ToolResult> {
    const [body, cost] = await this.client.get("/entities/trending", { time_filter: a.time_filter, limit: a.limit });
    const trending = isObj(body.trending) ? body.trending : {};
    const wanted = (a.entity_types || []).map((t) => t.trim()).filter((t) => t);
    const out: Record<string, unknown[]> = {};
    for (const etype of Object.keys(trending).sort()) {
      if (wanted.length && !wanted.includes(etype)) continue;
      if (!wanted.length && INDICATOR_TYPES.has(etype)) continue;
      const rows = arr(trending[etype]).filter((r) => isObj(r) && r.value);
      if (!rows.length) continue;
      out[etype] = rows.slice(0, a.limit).map((r) => ({ value: g(r, "value"), mentions: g(r, "frequency"), change_pct: g(r, "change"),
        is_new: Boolean(g(r, "is_new")), url: this.shape.entityUrl(etype, String(g(r, "value"))) }));
    }
    return [{ time_filter: g(body, "time_filter") || a.time_filter, entities: out }, cost];
  }

  async tool_api_budget(): Promise<ToolResult> {
    const snap = this.client.budget.snapshot() as any;
    return [{
      key_configured: this.client.hasKey,
      key_source: this.client.keySource,
      api_base: this.client.base,
      ...snap,
      advice: snap.session.api_calls === 0
        ? "No API call has been made yet in this session; the first tool call will populate the daily figures."
        : "Free keys: 100 credits/day, 30 requests/minute. Cheap reads cost 1, search_everything 5.",
    }, 0];
  }
}

export function renderPrompt(spec: PromptSpec, args: Record<string, string> | undefined): string {
  const now = new Date();
  const weekday = now.toLocaleDateString("en-GB", { weekday: "long", timeZone: "UTC" });
  const day = String(now.getUTCDate()).padStart(2, "0");
  const month = now.toLocaleDateString("en-GB", { month: "long", timeZone: "UTC" });
  const today = `${weekday} ${day} ${month} ${now.getUTCFullYear()} (UTC)`;
  const q = args && args.question !== undefined && args.question !== null ? String(args.question).trim() : "";
  const block = q ? `\n\nQuestion: ${q}` : "";
  return spec.template.split("{today}").join(today).split("{question_block}").join(block);
}
