# threatcluster-mcp (npm)

MCP server (stdio) for the [ThreatCluster](https://threatcluster.io) threat-intelligence API: incident clusters, entity profiles, CVE records and ransomware leak-site victims as ten read-only tools for Claude, Cursor, VS Code, Windsurf, Zed and any MCP client.

```bash
npx -y threatcluster-mcp
```

Configure `THREATCLUSTER_API_KEY` (free keys: <https://threatcluster.io/api>).

Claude Code:

```bash
claude mcp add threatcluster -e THREATCLUSTER_API_KEY=tc_live_... -- npx -y threatcluster-mcp
```

Claude Desktop / Cursor / Windsurf (`mcpServers` block):

```json
{ "threatcluster": { "command": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "tc_live_..." } } }
```

VS Code (`.vscode/mcp.json`):

```json
{ "servers": { "threatcluster": { "type": "stdio", "command": "npx", "args": ["-y", "threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "${input:tc-key}" } } },
  "inputs": [{ "type": "promptString", "id": "tc-key", "description": "ThreatCluster API key", "password": true }] }
```

`npx -y threatcluster-mcp --check` prints where the key came from and where it will be sent (never the key).

Tools: `search_threats`, `search_everything`, `newest_threats`, `get_threat`, `leak_site_victims`, `lookup_entity`, `get_vulnerability`, `exploited_vulnerabilities`, `trending_entities`, `api_budget`. Prompt: `threatcluster_analyst`. Every result carries `cost` (credits), `budget` (remaining today) and `url` fields for citation.

The key leaves the process only as the `X-API-Key` header to `THREATCLUSTER_API_BASE`; it is never logged and is scrubbed from every error. No telemetry. Identical to the PyPI package `threatcluster-mcp` (`uvx threatcluster-mcp`): both are generated from one tool spec and replay the same recorded fixtures byte-for-byte. Node 18+.

Full documentation, the tool table with credits per call and all client configs: <https://github.com/Jam0k/Threat-Intelligence-MCP> and <https://threatcluster.io/integrations/mcp>.
