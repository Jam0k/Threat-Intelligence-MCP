# mcp.so submission copy

Submit at https://mcp.so/submit (GitHub login; form fields below).

**Name:** ThreatCluster

**Repository:** https://github.com/Jam0k/Threat-Intelligence-MCP

**Homepage:** https://threatcluster.io/integrations/mcp

**Category:** Security / Threat intelligence

**Tags:** threat-intelligence, cti, cve, ransomware, dark-web, security, soc

**One-liner:** Live threat intelligence for agents: incident clusters, actor and malware profiles, CVEs with KEV/EPSS/exploit status, ransomware leak-site victims.

**Description:**

ThreatCluster clusters every public security report into one deduplicated story per incident, scores it, extracts the entities (actors, malware, tools, vendors, CVEs, countries, industries) and tracks ransomware leak sites. This MCP server exposes that corpus as ten read-only tools over the public REST API with your own key: `search_threats`, `search_everything`, `newest_threats`, `get_threat` (with IOCs), `leak_site_victims` (listings plus a tally by group/sector/country), `lookup_entity`, `get_vulnerability`, `exploited_vulnerabilities`, `trending_entities` and `api_budget` (so the agent can pace itself against the 100-credit-a-day free budget). Every result carries citation URLs and the credits it cost.

Runs anywhere: `npx -y threatcluster-mcp` (Node 18+) or `uvx threatcluster-mcp` (Python 3.10+); both builds come from one tool spec and are tested to produce identical output. The key is sent only as the `X-API-Key` header to threatcluster.io; no telemetry.

**Install (Claude Desktop / Cursor / Windsurf):**

```json
{ "mcpServers": { "threatcluster": { "command": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "tc_live_..." } } } }
```

Free API key: https://threatcluster.io/api
