# threatcluster-mcp (Python)

MCP server (stdio) for the [ThreatCluster](https://threatcluster.io) threat-intelligence API: incident clusters, entity profiles, CVE records and ransomware leak-site victims as ten read-only tools for Claude, Cursor, VS Code, Windsurf, Zed and any MCP client.

```bash
uvx threatcluster-mcp            # or: pipx run threatcluster-mcp
```

Configure `THREATCLUSTER_API_KEY` (free keys: <https://threatcluster.io/api>). If the [`tc` CLI](https://threatcluster.io/cli) is installed and you have run `tc auth login`, the credential is picked up from its store (keyring or the 0600 file) with no configuration.

Claude Code:

```bash
claude mcp add threatcluster -e THREATCLUSTER_API_KEY=tc_live_... -- uvx threatcluster-mcp
```

Claude Desktop / Cursor / Windsurf (`mcpServers` block):

```json
{ "threatcluster": { "command": "uvx", "args": ["threatcluster-mcp"], "env": { "THREATCLUSTER_API_KEY": "tc_live_..." } } }
```

`threatcluster-mcp --check` prints where the key came from and where it will be sent (never the key).

Tools: `search_threats`, `search_everything`, `newest_threats`, `get_threat`, `leak_site_victims`, `lookup_entity`, `get_vulnerability`, `exploited_vulnerabilities`, `trending_entities`, `api_budget`. Prompt: `threatcluster_analyst`. Every result carries `cost` (credits), `budget` (remaining today) and `url` fields for citation.

The key leaves the process only as the `X-API-Key` header to `THREATCLUSTER_API_BASE`; it is never logged and is scrubbed from every error. No telemetry. Identical to the npm package `threatcluster-mcp` (`npx -y threatcluster-mcp`): both are generated from one tool spec and replay the same recorded fixtures byte-for-byte.

Full documentation, the tool table with credits per call and all client configs: <https://github.com/Jam0k/Threat-Intelligence-MCP> and <https://threatcluster.io/integrations/mcp>.
