# Threat Intelligence MCP Server

An [MCP](https://modelcontextprotocol.io) server that gives Claude, Cursor, VS Code, Windsurf, Zed and any other MCP client live threat intelligence from [ThreatCluster](https://threatcluster.io): incident clusters (one deduplicated story per incident, with a threat score, timeline and extracted entities), entity profiles (actors, malware, tools, vendors, CVEs), CVE records with KEV / EPSS / exploit status, and ransomware leak-site victims.

It is a thin, auditable wrapper over the public REST API. Every tool call is one or two `GET`s to `https://threatcluster.io/api/public/v1` with **your** API key; nothing else leaves your machine, and there is no telemetry.

Published twice from one tool spec, so both are identical:

| Runtime | Install | Package |
|---|---|---|
| Python 3.10+ | `uvx threatcluster-mcp` (or `pipx run threatcluster-mcp`) | [PyPI: threatcluster-mcp](https://pypi.org/project/threatcluster-mcp/) |
| Node 18+ | `npx -y threatcluster-mcp` | [npm: threatcluster-mcp](https://www.npmjs.com/package/threatcluster-mcp) |

## 1. Get a key

Free keys carry the five read scopes, 100 credits a day, 30 requests a minute and a 7-day lookback: <https://threatcluster.io/api>. Put it in `THREATCLUSTER_API_KEY`. If you use the [`tc` CLI](https://threatcluster.io/cli) and have run `tc auth login`, the Python server picks that credential up automatically (keyring or the `~/.config/tc-cli/credentials` file); the Node server reads the file only.

## 2. Add the server

**Claude Code**

```bash
claude mcp add threatcluster -e THREATCLUSTER_API_KEY=tc_live_... -- npx -y threatcluster-mcp
# or the Python build:
claude mcp add threatcluster -e THREATCLUSTER_API_KEY=tc_live_... -- uvx threatcluster-mcp
```

**Claude Desktop** (`claude_desktop_config.json`, Settings > Developer > Edit Config)

```json
{
  "mcpServers": {
    "threatcluster": {
      "command": "npx",
      "args": ["-y", "threatcluster-mcp"],
      "env": { "THREATCLUSTER_API_KEY": "tc_live_..." }
    }
  }
}
```

**Cursor** — one-click: see [`listings/cursor-deeplink.md`](listings/cursor-deeplink.md), or add to `~/.cursor/mcp.json` / `.cursor/mcp.json`:

```json
{ "mcpServers": { "threatcluster": { "command": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "tc_live_..." } } } }
```

**VS Code** (`.vscode/mcp.json`; the input prompts for the key instead of storing it in the file)

```json
{
  "inputs": [{ "type": "promptString", "id": "tc-key", "description": "ThreatCluster API key", "password": true }],
  "servers": {
    "threatcluster": { "type": "stdio", "command": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "${input:tc-key}" } }
  }
}
```

**Windsurf** (`~/.codeium/windsurf/mcp_config.json`) — same `mcpServers` block as Claude Desktop.

**Zed** (`settings.json`)

```json
{ "context_servers": { "threatcluster": { "command": { "path": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "tc_live_..." } } } } }
```

Check a configuration without starting a client: `THREATCLUSTER_API_KEY=... npx -y threatcluster-mcp --check` (prints where the key came from and where it will be sent — never the key).

## 3. Tools

Costs are ThreatCluster API credits (free keys: 100 a day). Every result carries `cost` (credits this call spent), `budget` (remaining today, from the response headers), `as_of`, and `url` fields on every cluster, entity, victim and CVE for citation.

| Tool | What it answers | API endpoint(s) | Credits |
|---|---|---|---|
| `search_threats` | Keyword search over incident clusters; phrase, then all words, then any word; `matched_stage` says which | `GET /threats?keyword=` per term | 1 per term (max 8 calls) |
| `search_everything` | Clusters, entity profiles and dark-web hits in one call | `GET /search` | 5 |
| `newest_threats` | What is new in 1h / 24h / 7d / 30d, by first report or by momentum | `GET /threats` | 1 |
| `get_threat` | Full record for one cluster: summary, timeline, articles, entities; `include_iocs` adds validated indicators | `GET /threats/{id}` (+ `/iocs`) | 1 (+1) |
| `leak_site_victims` | Ransomware leak-site listings by sector / group / country / victim, plus a tally of the whole window | `GET /darkweb/ransomware/victims` + `/facets` | 2 |
| `lookup_entity` | Profile of an actor, malware, tool, vendor, product, country, industry or CVE | `GET /entities/search` + `GET /entities/{type}/{value}` | 2 |
| `get_vulnerability` | One CVE: CVSS, EPSS, KEV with due date, exploits, vendors, products | `GET /vulnerabilities/{cve_id}` | 1 |
| `exploited_vulnerabilities` | CVEs in a window filtered to KEV / public exploit / severity / vendor / product | `GET /vulnerabilities` | 1 |
| `trending_entities` | Actors, malware, tools, vendors, CVEs, countries rising over a window | `GET /entities/trending` | 1 |
| `api_budget` | Remaining credits and rate state from the last responses — no API call | — | 0 |

One prompt, `threatcluster_analyst`, carries the analyst rules (tools first, cite every fact with the returned `url`, say what period you searched, leak-site listings are claims).

Errors come back as MCP tool errors with the API's own message: `401` tells the agent to set `THREATCLUSTER_API_KEY` and where a free key comes from, `429` carries the `Retry-After`, `403` names the missing scope or the lookback window and the plan that lifts it.

## Security

- The key is read from `THREATCLUSTER_API_KEY` (then `TC_REFRESH_TOKEN`, then the tc-cli store) and sent only as the `X-API-Key` header (or `Authorization: Bearer` for a JWT minted by `tc login`) to `THREATCLUSTER_API_BASE`.
- It is never logged, never printed by `--check`, never written to disk, and scrubbed from every error string; the test suites assert the key is absent from all stdout and stderr bytes, including on a 401 whose body quotes it.
- stdio only. No outbound connection other than the API. No analytics.
- All tools are read-only (`readOnlyHint: true`) and validate arguments against the spec before any request is made.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `THREATCLUSTER_API_KEY` | — | your key (`tc_live_…`, `tc_agent_…`) or a bearer from `tc login` |
| `THREATCLUSTER_API_BASE` | `https://threatcluster.io/api/public/v1` | API base (self-hosted or local test servers) |
| `THREATCLUSTER_SITE` | `https://threatcluster.io` | base for the `url` fields in results |

## Repository layout

```
tools/tools.json   the single source of truth: tools, schemas, endpoint mapping, credits, prompt
python/            PyPI package (hatchling; mcp + httpx)          -> console script threatcluster-mcp
node/              npm package (TypeScript; @modelcontextprotocol/sdk + zod) -> bin threatcluster-mcp
tests/fixtures/    recorded API responses and tool outputs; both packages must replay them identically
listings/          directory manifests and submission copy (Smithery, MCP registry, Glama, mcp.so, Cursor, VS Code)
.github/workflows/ CI (both suites) and tag-triggered publishing (PyPI trusted publishing, npm provenance)
```

`python3 tools/sync_tools.py` copies the spec into both packages; CI fails if the copies drift.

## Development

```bash
pip install -e "python/[test]" && (cd python && pytest)
cd node && npm install && npm test
# live validation against a real API (spends ~30 credits, re-records tests/fixtures):
THREATCLUSTER_LIVE=1 THREATCLUSTER_API_KEY=... THREATCLUSTER_API_BASE=... pytest python/tests/test_live.py
```

Related: the [`tc` CLI](https://threatcluster.io/cli), the [API reference](https://threatcluster.io/api/public/v1/docs), the [agent-tool recipe](https://threatcluster.io/build/agent-tool) for a bare tool-calling function, and the [integration guide](https://threatcluster.io/integrations/mcp).

GPL-3.0-or-later © ThreatCluster Ltd.
