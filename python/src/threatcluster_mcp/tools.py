"""Tool spec loading, argument validation and result shaping.

The spec (``tools.json``) is the single source of truth shared with the npm
package; this module only turns validated arguments into API calls and API
rows into compact, citable results. The shaping here is mirrored line for
line in ``node/src/tools.ts`` — the replay tests assert both produce the same
JSON for the same recorded API responses.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from importlib import resources
from typing import Any, Optional
from urllib.parse import quote

from .client import ApiError, ThreatClusterClient, now_iso

# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------
_SPEC: Optional[dict] = None


def load_spec() -> dict:
    global _SPEC
    if _SPEC is None:
        with resources.files(__package__).joinpath("tools.json").open("r", encoding="utf-8") as f:
            _SPEC = json.load(f)
    return _SPEC


def tool_specs() -> list[dict]:
    return list(load_spec()["tools"])


def tool_spec(name: str) -> Optional[dict]:
    for t in load_spec()["tools"]:
        if t["name"] == name:
            return t
    return None


def prompt_specs() -> list[dict]:
    return list(load_spec()["prompts"])


# ---------------------------------------------------------------------------
# Argument validation (deliberately hand-rolled: same messages as the node
# package, no jsonschema dependency, stricter than draft-7 defaults because
# additionalProperties is always false in the spec)
# ---------------------------------------------------------------------------
class ToolInputError(ValueError):
    pass


def _check(name: str, ps: dict, v: Any) -> Any:
    t = ps.get("type")
    if t == "string":
        if not isinstance(v, str):
            raise ToolInputError(f"argument '{name}' must be a string")
        if "enum" in ps and v not in ps["enum"]:
            raise ToolInputError(f"argument '{name}' must be one of: {', '.join(ps['enum'])}")
        lo, hi = ps.get("minLength"), ps.get("maxLength")
        if (lo is not None and len(v) < lo) or (hi is not None and len(v) > hi):
            raise ToolInputError(f"argument '{name}' must be between {lo or 0} and {hi if hi is not None else 'unlimited'} characters")
        if "pattern" in ps and re.search(ps["pattern"], v) is None:
            raise ToolInputError(f"argument '{name}' does not match the expected format ({ps.get('description') or ps['pattern']})")
        return v
    if t == "integer":
        if isinstance(v, bool) or not isinstance(v, int):
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            else:
                raise ToolInputError(f"argument '{name}' must be an integer")
        lo, hi = ps.get("minimum"), ps.get("maximum")
        if (lo is not None and v < lo) or (hi is not None and v > hi):
            raise ToolInputError(f"argument '{name}' must be an integer between {lo} and {hi}")
        return v
    if t == "boolean":
        if not isinstance(v, bool):
            raise ToolInputError(f"argument '{name}' must be true or false")
        return v
    if t == "array":
        if not isinstance(v, list):
            raise ToolInputError(f"argument '{name}' must be a list")
        mx = ps.get("maxItems")
        if mx is not None and len(v) > mx:
            raise ToolInputError(f"argument '{name}' must be a list of at most {mx} items")
        items = ps.get("items")
        return [_check(f"{name}[{i}]", items, x) for i, x in enumerate(v)] if items else list(v)
    return v


def validate_args(schema: dict, args: Any) -> dict:
    """Validate ``args`` against a tool's inputSchema and fill defaults.
    Raises :class:`ToolInputError` with an agent-readable message."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolInputError("arguments must be an object")
    props: dict = schema.get("properties") or {}
    for k in args:
        if k not in props:
            raise ToolInputError(f"unknown argument '{k}'")
    for k in schema.get("required") or []:
        if args.get(k) is None:
            raise ToolInputError(f"missing required argument '{k}'")
    out: dict[str, Any] = {}
    for k, ps in props.items():
        if k in args and args[k] is not None:
            out[k] = _check(k, ps, args[k])
        elif "default" in ps:
            out[k] = ps["default"]
    return out


# ---------------------------------------------------------------------------
# Shaping helpers (mirrored in node/src/tools.ts)
# ---------------------------------------------------------------------------
STOP_WORDS = {"the", "a", "an", "of", "in", "on", "for", "to", "and", "or", "with", "by", "from", "at", "is", "are",
              "was", "were", "be", "about", "into", "recent", "recently", "latest", "new", "attack", "attacks",
              "incident", "incidents", "threat", "threats"}
_WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.\-]+")
PRIMARY_ENTITY_TYPES = ["apt_group", "ransomware_group", "malware", "tool", "campaign", "cve", "company", "platform",
                        "country", "industry", "attack_type", "mitre_attack"]
INDICATOR_TYPES = {"ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256", "btc", "eth", "xmr"}
MAX_SEARCH_CALLS = 8
# A stage is good enough to stop laddering at this many hits (search_threats
# uses the same number for its phrase -> all words -> any word walk).
ENOUGH_HITS = 3
# Words fanned out per search_everything call; caps the credit cost of a
# long query the way MAX_SEARCH_CALLS caps search_threats.
MAX_SEARCH_WORDS = 4
TIME_FILTER_DAYS = {"24h": 1, "7d": 7, "14d": 14, "30d": 30, "90d": 90}


def trunc(s: Any, n: int) -> Optional[str]:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n].rstrip() + "…"


def date_only(v: Any) -> Optional[str]:
    if v is None or v == "":
        return None
    return str(v)[:10]


def short_id(cluster_id: Any) -> str:
    return str(cluster_id or "").replace("-", "")[-8:]


def words_of(query: str) -> list[str]:
    return [w for w in _WORD_RE.findall(query) if w.lower() not in STOP_WORDS]


def days_to_time_filter(days: Optional[int]) -> str:
    """Map a day count onto the nearest backend time_filter that is >= it.

    Previously anything over 7 became "30d", so days=90 searched 30 days and
    reported window_searched="30d" with no indication the request had been
    narrowed. The backend allowlists 14d/30d/90d and applies its own per-tier
    clamp, so send the real window and let the server decide.
    """
    if days is None:
        return "7d"
    if days <= 1:
        return "24h"
    if days <= 7:
        return "7d"
    if days <= 14:
        return "14d"
    if days <= 30:
        return "30d"
    return "90d"


def normalise_entities(ents: Any) -> dict[str, list[str]]:
    """Cluster entities arrive as {type: [values]} (detail / free) or as a list
    of {entity_type, entity_value} rows. Return {type: [str values]}."""
    out: dict[str, list[str]] = {}
    if isinstance(ents, dict):
        for t, vals in ents.items():
            if not isinstance(vals, list):
                continue
            out[t] = [str(v.get("value") or v.get("entity_value") or "") if isinstance(v, dict) else str(v) for v in vals]
    elif isinstance(ents, list):
        for row in ents:
            if isinstance(row, dict) and row.get("entity_type"):
                out.setdefault(str(row["entity_type"]), []).append(str(row.get("entity_value") or row.get("value") or ""))
    return {t: [v for v in vals if v] for t, vals in out.items() if vals}


class Shaper:
    def __init__(self, site: str) -> None:
        self.site = site.rstrip("/")

    # -- urls --------------------------------------------------------------
    def cluster_url(self, c: dict) -> str:
        ident = c.get("slug") or c.get("short_id") or short_id(c.get("cluster_id"))
        return f"{self.site}/cluster/{ident}"

    def entity_url(self, etype: str, value: str) -> str:
        return f"{self.site}/entities/{str(etype).replace('_', '-')}/{quote(str(value), safe='')}"

    def group_url(self, group: str) -> str:
        return f"{self.site}/dark-web/group/{quote(str(group), safe='')}"

    def victim_url(self, v: dict) -> str:
        if v.get("id"):
            return f"{self.site}/dark-web/victim/{quote(str(v['id']), safe='')}"
        return self.group_url(str(v.get("group") or ""))

    def cve_url(self, cve_id: str) -> str:
        return f"{self.site}/entities/cve/{quote(str(cve_id).upper(), safe='')}"

    # -- rows --------------------------------------------------------------
    def cluster(self, c: dict, summary_chars: int = 350) -> dict:
        ents = normalise_entities(c.get("entities"))
        return {
            "cluster_id": c.get("cluster_id"),
            "short_id": c.get("short_id") or short_id(c.get("cluster_id")),
            "title": c.get("ai_title") or c.get("title"),
            "date": date_only(c.get("date_range_latest") or c.get("updated_at") or c.get("created_at")),
            "threat_score": c.get("threat_score"),
            "urgency": c.get("urgency_level"),
            "article_count": c.get("article_count"),
            "summary": trunc(c.get("ai_summary"), summary_chars),
            "sources": list(c.get("sources") or [])[:5],
            "entities": {t: ents[t][:6] for t in PRIMARY_ENTITY_TYPES if ents.get(t)},
            "url": self.cluster_url(c),
        }

    def cluster_brief(self, c: dict) -> dict:
        return {
            "cluster_id": c.get("cluster_id"),
            "title": c.get("ai_title") or c.get("title"),
            "date": date_only(c.get("date_range_latest") or c.get("updated_at") or c.get("created_at")),
            "threat_score": c.get("threat_score"),
            "url": self.cluster_url(c),
        }

    def cluster_detail(self, c: dict) -> dict:
        ents = normalise_entities(c.get("entities"))
        timeline = [e for e in (c.get("timeline") or []) if isinstance(e, dict)]
        articles = [a for a in (c.get("articles") or []) if isinstance(a, dict) and not a.get("is_reference_only")]
        out: dict[str, Any] = {
            "cluster_id": c.get("cluster_id"),
            "short_id": c.get("short_id") or short_id(c.get("cluster_id")),
            "title": c.get("ai_title") or c.get("title"),
            "date": date_only(c.get("date_range_latest") or c.get("updated_at") or c.get("created_at")),
            "first_seen": date_only(c.get("date_range_earliest") or c.get("created_at")),
            "threat_score": c.get("threat_score"),
            "urgency": c.get("urgency_level"),
            "article_count": c.get("article_count"),
            "summary": trunc(c.get("ai_summary"), 1500),
            "analysis": trunc(c.get("enhanced_summary"), 1200) if c.get("enhanced_summary") else None,
            "keywords": list(c.get("keywords") or [])[:10],
            "sources": list(c.get("sources") or [])[:10],
            "timeline": [{
                "date": date_only(e.get("date")),
                "event": trunc(e.get("event") or e.get("description"), 200),
                "detail": trunc(e.get("detail"), 240),
                "source": e.get("source"),
                "source_url": e.get("source_url"),
            } for e in timeline[:8]],
            "timeline_truncated": bool(c.get("timeline_truncated")) or len(timeline) > 8,
            "entities": {t: vals[:10] for t, vals in ents.items()},
            "articles": [{
                "date": date_only(a.get("pub_date")),
                "source": a.get("source"),
                "title": a.get("title"),
                "url": a.get("url"),
            } for a in articles[:8]],
            "url": self.cluster_url(c),
            "tier": c.get("tier"),
        }
        if out["analysis"] is None:
            del out["analysis"]
        return out

    def cve(self, c: dict, full: bool) -> dict:
        out: dict[str, Any] = {
            "cve_id": c.get("cve_id"),
            "description": trunc(c.get("description"), 600 if full else 240),
            "cvss": {"score": c.get("cvss_v3_score"), "severity": c.get("cvss_v3_severity")},
            "epss": {"score": c.get("epss_score"), "percentile": c.get("epss_percentile")},
            "in_kev": c.get("in_kev"),
            "kev_added_date": c.get("kev_added_date"),
            "kev_due_date": c.get("kev_due_date"),
            "ransomware_use": c.get("ransomware_use"),
            "has_exploit": c.get("has_exploit"),
            "exploit_count": c.get("exploit_count"),
            "vendors": list(c.get("affected_vendors") or [])[:10],
            "products": list(c.get("affected_products") or [])[:10],
            "published": date_only(c.get("published_date")),
            "last_modified": date_only(c.get("last_modified")),
            "url": self.cve_url(str(c.get("cve_id") or "")),
        }
        if full:
            out["cvss"]["vector"] = c.get("cvss_v3_vector")
            out["cwe_ids"] = list(c.get("cwe_ids") or [])
            out["exploit_urls"] = list(c.get("exploit_urls") or [])[:5]
            refs = c.get("reference_urls") or []
            out["references"] = [(r.get("url") if isinstance(r, dict) else str(r)) for r in refs][:5]
        return out

    def victim(self, v: dict) -> dict:
        return {
            "date": date_only(v.get("discovered")),
            "group": v.get("group") or v.get("group_name"),
            "victim": v.get("name") or v.get("victim_name"),
            "sector": v.get("sector"),
            "country": v.get("country"),
            "website": v.get("website"),
            "url": self.victim_url(v),
        }


IOC_KEYS = ["type", "ioc_type", "value", "confidence", "reason", "context", "first_seen", "last_seen", "source", "tags"]


def compact_ioc(row: Any) -> Any:
    if not isinstance(row, dict):
        return row
    picked = {k: row[k] for k in IOC_KEYS if k in row}
    return picked or row


# ---------------------------------------------------------------------------
# Runner: one method per tool
# ---------------------------------------------------------------------------
class ToolRunner:
    def __init__(self, client: ThreatClusterClient) -> None:
        self.client = client
        self.shape = Shaper(client.site)

    async def run(self, name: str, args: dict) -> dict:
        fn = getattr(self, f"tool_{name}", None)
        if fn is None:
            raise ToolInputError(f"unknown tool '{name}'")
        data, cost = await fn(**args)
        result: dict[str, Any] = {"tool": name, "as_of": now_iso(), "cost": cost, "budget": self.client.budget.brief()}
        result.update(data)
        return result

    # -- search_threats ----------------------------------------------------
    async def tool_search_threats(self, query: str, alternatives: Optional[list[str]] = None,
                                  days: Optional[int] = None, limit: int = 8):
        query = query.strip()
        alts = [a.strip() for a in (alternatives or []) if a.strip()]
        words = words_of(query)
        initial_tf = days_to_time_filter(days)
        stages: list[tuple[str, list[str], bool]] = [("phrase", [query] + alts, False)]
        if len(words) >= 2:
            stages.append(("words", words[:4], True))
        calls = 0
        cost = 0
        terms_searched: list[str] = []
        found: list[dict] = []
        matched_stage: Optional[str] = None
        window_used = initial_tf
        widened = False

        async def fetch(term: str, tf: str) -> list[dict]:
            nonlocal calls, cost, window_used, lookback_days
            calls += 1
            terms_searched.append(term)
            body, c = await self.client.get("/threats", {"keyword": term, "limit": 25, "time_filter": tf})
            cost += c
            if isinstance(body, dict) and body.get("time_filter"):
                window_used = str(body["time_filter"])
            if isinstance(body, dict) and isinstance(body.get("lookback_days"), int):
                lookback_days = body["lookback_days"]
            return [r for r in (body.get("threats") or []) if isinstance(r, dict) and r.get("cluster_id")]

        def dedupe(rows: list[dict]) -> list[dict]:
            seen: set[str] = set()
            out: list[dict] = []
            for r in rows:
                cid = str(r["cluster_id"])
                if cid not in seen:
                    seen.add(cid)
                    out.append(r)
            return out

        lookback_days: Optional[int] = None
        windows = [initial_tf] + [w for w in ("30d", "90d")
                                   if TIME_FILTER_DAYS.get(w, 0) > TIME_FILTER_DAYS.get(initial_tf, 0)]
        for wi, tf in enumerate(windows):
            found_before = len(found)
            for stage_name, terms, is_words in stages:
                if calls >= MAX_SEARCH_CALLS:
                    break
                per_term: list[list[dict]] = []
                for term in terms:
                    if calls >= MAX_SEARCH_CALLS:
                        break
                    per_term.append(await fetch(term, tf))
                if not per_term:
                    continue
                if is_words:
                    ids = [set(str(r["cluster_id"]) for r in rows) for rows in per_term]
                    common = set.intersection(*ids) if ids else set()
                    all_words = dedupe([r for rows in per_term for r in rows if str(r["cluster_id"]) in common])
                    if len(all_words) > len(found):
                        found, matched_stage = all_words, "all words"
                    if len(found) >= 3:
                        break
                    any_word = dedupe([r for rows in per_term for r in rows])
                    if len(any_word) > len(found):
                        found, matched_stage = any_word, "any word"
                else:
                    rows = dedupe([r for rows in per_term for r in rows])
                    if len(rows) > len(found):
                        found, matched_stage = rows, "phrase"
                if len(found) >= 3:
                    break
            if wi > 0 and len(found) > found_before:
                widened = True
            if len(found) >= 3 or calls >= MAX_SEARCH_CALLS:
                break
            # A free key is clamped to its lookback window; widening past it
            # would only repeat the same calls (and spend the same credits).
            if lookback_days is not None and lookback_days <= TIME_FILTER_DAYS.get(tf, 7):
                break
        found.sort(key=lambda r: -(r.get("threat_score") or 0))
        return {
            "query": query,
            "alternatives": alts,
            "days": days,
            "window_searched": window_used,
            "widened_beyond_days": widened,
            "matched_stage": matched_stage if found else None,
            "terms_searched": terms_searched,
            "api_calls": calls,
            "count": min(len(found), limit),
            "clusters": [self.shape.cluster(c) for c in found[:limit]],
        }, cost

    # -- search_everything -------------------------------------------------
    async def tool_search_everything(self, query: str, days: Optional[int] = None, limit: int = 5):
        """Unified search with the same fallback ladder as search_threats.

        GET /search is a literal substring match, so a descriptive query
        ("Qilin ransomware group") matched nothing while its head word
        ("Qilin") matched 24 hits — and the empty result was indistinguishable
        from an empty corpus. Retry with progressively looser terms and report
        which stage matched.
        """
        q0 = query.strip()
        words = words_of(q0)[:MAX_SEARCH_WORDS]

        def key_of(bucket: str, row: dict) -> str:
            """Stable identity per bucket, so rows can be intersected/unioned."""
            if bucket == "clusters":
                return str(row.get("cluster_id") or row.get("short_id") or id(row))
            if bucket == "entities":
                return f"{row.get('entity_type')}\u241f{row.get('entity_value')}"
            return str(row.get("url") or f"{row.get('type')}\u241f{row.get('name')}")

        def merge(bodies: list[dict], common_only: bool) -> dict:
            """Union the buckets across per-word results; when common_only, keep
            just the rows every word returned (the 'all words' reading)."""
            out: dict = {}
            for bucket in ("clusters", "entities", "darkweb"):
                per_word = [{key_of(bucket, r): r for r in (b.get(bucket) or []) if isinstance(r, dict)}
                            for b in bodies]
                per_word = [m for m in per_word if m] if common_only else per_word
                if not per_word:
                    out[bucket] = []
                    continue
                keys = set.intersection(*(set(m) for m in per_word)) if common_only else \
                       set().union(*(set(m) for m in per_word))
                seen, rows = set(), []
                for m in per_word:
                    for k, r in m.items():
                        if k in keys and k not in seen:
                            seen.add(k)
                            rows.append(r)
                out[bucket] = rows
            for meta in ("days", "lookback_days", "total"):
                for b in bodies:
                    if b.get(meta) is not None:
                        out.setdefault(meta, b[meta])
                        break
            return out

        def size(b: dict) -> int:
            return sum(len(b.get(k) or []) for k in ("clusters", "entities", "darkweb"))

        body: dict = {}
        cost = 0
        matched_stage = None
        best = -1

        # Stage 1: the phrase exactly as asked.
        b, c = await self.client.get("/search", {"q": q0, "limit": limit, "days": days})
        cost += c
        b = b if isinstance(b, dict) else {}
        body, matched_stage, best = b, "phrase", size(b)

        # Stages 2 and 3 fan out ONE CALL PER WORD, the way search_threats does.
        # Joining the words back into a string only re-ran the phrase (GET
        # /search is a substring match), and picking the longest word chose
        # "ransomware" over "Qilin" — 2,250 generic clusters instead of the 135
        # that matter. Intersecting per-word results keeps "all words" specific;
        # the union is the last resort.
        if best < ENOUGH_HITS and len(words) >= 2:
            per: list[dict] = []
            for w in words:
                if len(w) < 2:
                    continue
                wb, wc = await self.client.get("/search", {"q": w, "limit": limit, "days": days})
                cost += wc
                per.append(wb if isinstance(wb, dict) else {})
            if per:
                both = merge(per, common_only=True)
                if size(both) > best:
                    body, matched_stage, best = both, "all words", size(both)
                if best < ENOUGH_HITS:
                    either = merge(per, common_only=False)
                    if size(either) > best:
                        body, matched_stage, best = either, "any word", size(either)
        entities = [{
            "type": e.get("entity_type"),
            "value": e.get("entity_value"),
            "cluster_count": e.get("cluster_count"),
            "article_count": e.get("article_count"),
            "url": self.shape.entity_url(str(e.get("entity_type") or ""), str(e.get("entity_value") or "")),
        } for e in (body.get("entities") or [])[:limit] if isinstance(e, dict)]
        darkweb = []
        for d in (body.get("darkweb") or [])[:limit]:
            if not isinstance(d, dict):
                continue
            kind = d.get("type")
            url = (self.shape.victim_url(d) if kind == "victim"
                   else self.shape.group_url(str(d.get("name") or "")) if kind == "group"
                   else f"{self.shape.site}/dark-web")
            darkweb.append({"type": kind, "name": d.get("name"), "date": date_only(d.get("date")), "group": d.get("group"),
                            "country": d.get("country"), "sector": d.get("sector"), "url": url})
        return {
            "query": q0,
            "matched_stage": matched_stage,
            "days": body.get("days") or body.get("lookback_days"),
            "total": body.get("total"),
            "clusters": [self.shape.cluster(c) for c in (body.get("clusters") or [])[:limit] if isinstance(c, dict)],
            "entities": entities,
            "darkweb": darkweb,
        }, cost

    # -- newest_threats ----------------------------------------------------
    async def tool_newest_threats(self, time_filter: str = "24h", limit: int = 12, sort_by: str = "new"):
        body, cost = await self.client.get("/threats", {"time_filter": time_filter, "limit": limit, "sort_by": sort_by})
        return {
            "time_filter": body.get("time_filter") or time_filter,
            "sort_by": sort_by,
            "count": len(body.get("threats") or []),
            "clusters": [self.shape.cluster(c, 300) for c in (body.get("threats") or [])[:limit] if isinstance(c, dict)],
        }, cost

    # -- get_threat ----------------------------------------------------------
    async def tool_get_threat(self, identifier: str, include_iocs: bool = False):
        ident = identifier.strip()
        body, cost = await self.client.get(f"/threats/{quote(ident, safe='')}")
        out = self.shape.cluster_detail(body)
        if include_iocs:
            cid = str(body.get("cluster_id") or ident)
            iocs, c2 = await self.client.get(f"/threats/{quote(cid, safe='')}/iocs", {"format": "json"})
            cost += c2
            rows = iocs.get("iocs") if isinstance(iocs, dict) else None
            if rows is None and isinstance(iocs, list):
                rows = iocs
            rows = rows or []
            out["iocs"] = {"count": iocs.get("count", len(rows)) if isinstance(iocs, dict) else len(rows),
                           "indicators": [compact_ioc(r) for r in rows[:50]]}
        return out, cost

    # -- leak_site_victims ---------------------------------------------------
    async def tool_leak_site_victims(self, days: int = 7, sector: Optional[str] = None, group: Optional[str] = None,
                                     country: Optional[str] = None, victim: Optional[str] = None, limit: int = 15):
        params = {"days": days, "limit": 100 if victim else limit, "group": group, "country": country.upper() if country else None,
                  "sector": sector}
        body, cost = await self.client.get("/darkweb/ransomware/victims", params)
        rows = [v for v in (body.get("victims") or []) if isinstance(v, dict)]
        if victim:
            needle = victim.lower()
            rows = [v for v in rows if needle in f"{v.get('name') or ''} {v.get('website') or ''}".lower()]
        facets, c2 = await self.client.get("/darkweb/ransomware/victims/facets", {"days": days})
        cost += c2

        def tally(key: str, n: int) -> list[dict]:
            return [{"value": f.get("value"), "count": f.get("count")} for f in (facets.get(key) or [])[:n] if isinstance(f, dict)]

        by_group = [{"group": f["value"], "count": f["count"], "url": self.shape.group_url(str(f["value"]))} for f in tally("groups", 12)]
        window_total = sum(int(f.get("count") or 0) for f in (facets.get("groups") or []) if isinstance(f, dict))
        filters = {k: v for k, v in {"sector": sector, "group": group, "country": country.upper() if country else None,
                                     "victim": victim}.items() if v}
        return {
            "days": body.get("lookback_days") if body.get("lookback_days") and int(body["lookback_days"]) < days else days,
            "filters": filters,
            "window_total_listings": window_total,
            "by_group": by_group,
            "by_sector": tally("sectors", 10),
            "by_country": tally("countries", 8),
            "listings_count": min(len(rows), limit),
            "listings": [self.shape.victim(v) for v in rows[:limit]],
            "note": ("Listings are claims by the groups, not confirmed breaches. The tally covers every listing in the window "
                     "(all groups, sectors and countries); the listings are the newest that match the filters."),
        }, cost

    # -- lookup_entity ---------------------------------------------------------
    async def tool_lookup_entity(self, name: str, entity_type: Optional[str] = None):
        name = name.strip()
        body, cost = await self.client.get("/entities/search", {"q": name, "entity_type": entity_type, "limit": 5})
        hits = [h for h in (body.get("entities") or []) if isinstance(h, dict) and h.get("entity_value")]
        if not hits:
            return {"found": False, "name": name, "entity_type": entity_type,
                    "message": f"no entity in the corpus matches '{name}'" + (f" of type {entity_type}" if entity_type else "")}, cost
        top = hits[0]
        etype = str(top.get("entity_type") or entity_type or "")
        evalue = str(top["entity_value"])
        detail, c2 = await self.client.get(f"/entities/{quote(etype, safe='')}/{quote(evalue, safe='')}")
        cost += c2
        ent = detail.get("entity") if isinstance(detail.get("entity"), dict) else {}
        co = normalise_entities(detail.get("co_entities"))
        return {
            "found": True,
            "entity": {
                "type": etype,
                "value": ent.get("entity_value") or evalue,
                "mentions": ent.get("frequency") if ent.get("frequency") is not None else top.get("article_count"),
                "cluster_count": top.get("cluster_count"),
                "article_count": top.get("article_count"),
                "first_seen": date_only(ent.get("first_seen")),
                "last_seen": date_only(ent.get("last_seen")),
                "url": self.shape.entity_url(etype, ent.get("entity_value") or evalue),
            },
            "aliases": list(detail.get("aliases") or [])[:10],
            "recent_clusters": [self.shape.cluster_brief(c) for c in (detail.get("clusters") or [])[:5] if isinstance(c, dict)],
            "recent_articles": [{"date": date_only(a.get("pub_date")), "source": a.get("source"), "title": a.get("title"),
                                 "url": a.get("url")} for a in (detail.get("articles") or [])[:5] if isinstance(a, dict)],
            "related": {t: co[t][:6] for t in PRIMARY_ENTITY_TYPES if co.get(t)},
            "totals": {"clusters": detail.get("clusters_total"), "articles": detail.get("articles_total")},
            "other_matches": [{"value": h.get("entity_value"), "type": h.get("entity_type")} for h in hits[1:4]],
            "lookback_days": detail.get("lookback_days"),
        }, cost

    # -- get_vulnerability -------------------------------------------------------
    async def tool_get_vulnerability(self, cve_id: str):
        cve = cve_id.strip().upper()
        body, cost = await self.client.get(f"/vulnerabilities/{quote(cve, safe='')}")
        return self.shape.cve(body, full=True), cost

    # -- exploited_vulnerabilities -------------------------------------------------
    async def tool_exploited_vulnerabilities(self, days: int = 7, kev_only: bool = True, has_exploit: bool = False,
                                             severity: Optional[str] = None, vendor: Optional[str] = None,
                                             product: Optional[str] = None, limit: int = 15):
        params = {"days": days, "kev_only": "true" if kev_only else "false", "has_exploit": "true" if has_exploit else "false",
                  "severity": severity, "vendor": vendor, "product": product, "limit": limit}
        body, cost = await self.client.get("/vulnerabilities", params)
        filters = {k: v for k, v in {"kev_only": kev_only, "has_exploit": has_exploit, "severity": severity, "vendor": vendor,
                                     "product": product}.items() if v}
        return {
            "days": body.get("days") or days,
            "filters": filters,
            "total": body.get("total"),
            "count": len(body.get("cves") or []),
            "cves": [self.shape.cve(c, full=False) for c in (body.get("cves") or [])[:limit] if isinstance(c, dict)],
        }, cost

    # -- trending_entities -----------------------------------------------------------
    async def tool_trending_entities(self, time_filter: str = "7d", entity_types: Optional[list[str]] = None, limit: int = 5):
        body, cost = await self.client.get("/entities/trending", {"time_filter": time_filter, "limit": limit})
        trending = body.get("trending") if isinstance(body.get("trending"), dict) else {}
        wanted = [t.strip() for t in (entity_types or []) if t.strip()]
        out: dict[str, list[dict]] = {}
        for etype in sorted(trending.keys()):
            if wanted and etype not in wanted:
                continue
            if not wanted and etype in INDICATOR_TYPES:
                continue
            rows = [r for r in (trending.get(etype) or []) if isinstance(r, dict) and r.get("value")]
            if not rows:
                continue
            out[etype] = [{"value": r.get("value"), "mentions": r.get("frequency"), "change_pct": r.get("change"),
                           "is_new": bool(r.get("is_new")), "url": self.shape.entity_url(etype, str(r.get("value")))}
                          for r in rows[:limit]]
        return {"time_filter": body.get("time_filter") or time_filter, "entities": out}, cost

    # -- api_budget ------------------------------------------------------------------
    async def tool_api_budget(self):
        snap = self.client.budget.snapshot()
        return {
            "key_configured": self.client.has_key,
            "key_source": self.client.key_source,
            "api_base": self.client.base,
            **snap,
            "advice": ("No API call has been made yet in this session; the first tool call will populate the daily figures."
                       if snap["session"]["api_calls"] == 0 else
                       "Free keys: 100 credits/day, 30 requests/minute. Cheap reads cost 1, search_everything 5."),
        }, 0


def render_prompt(spec: dict, args: Optional[dict]) -> str:
    today = datetime.now(timezone.utc).strftime("%A %d %B %Y (UTC)")
    q = (args or {}).get("question")
    q = str(q).strip() if q is not None else ""
    block = f"\n\nQuestion: {q}" if q else ""
    return spec["template"].replace("{today}", today).replace("{question_block}", block)
