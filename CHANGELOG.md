# Changelog

All notable changes to `threatcluster-mcp` (both the PyPI and npm packages; they share a version).
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-09-04

### Added
- First release. Ten read-only tools over the ThreatCluster public API v1: `search_threats`,
  `search_everything`, `newest_threats`, `get_threat`, `leak_site_victims`, `lookup_entity`,
  `get_vulnerability`, `exploited_vulnerabilities`, `trending_entities`, `api_budget`.
- One prompt, `threatcluster_analyst`, with the citation rules.
- Single tool spec (`tools/tools.json`) shared by the Python (`uvx threatcluster-mcp`) and
  Node (`npx -y threatcluster-mcp`) packages; replay tests assert byte-identical output.
- Credential resolution: `THREATCLUSTER_API_KEY`, then `TC_REFRESH_TOKEN`, then the tc-cli store.
- Budget tracking from `X-Request-Cost` / `X-RateLimit-*` headers; `cost` and `budget` on every result.
- Error mapping: 401 (key hint + free-key URL), 403 (scope / lookback + plan), 429 (`Retry-After`), 404.
- Key redaction on every string that reaches the MCP transport; leak tests over raw stdout/stderr.
