# Installing the ThreatCluster MCP server

Two ways to run it. Both need a ThreatCluster API key: free on every account at https://threatcluster.io/api (100 credits a day).

## 1. Hosted (no install)

Point the client at the hosted endpoint with the key in the `X-API-Key` header.

```json
{
  "mcpServers": {
    "threatcluster": {
      "url": "https://threatcluster.io/mcp",
      "headers": { "X-API-Key": "tc_live_..." }
    }
  }
}
```

## 2. Local, via npm (Node 18+)

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

Python alternative (3.10+): `"command": "uvx", "args": ["threatcluster-mcp"]` with the same `env`.

## Verify

Ask the assistant to call `api_budget`. It returns the key's remaining credits without spending any. Then try `newest_threats` with `hours: 24`.

## Notes

- Ten read-only tools; nothing writes to ThreatCluster.
- The key is sent only to threatcluster.io. No telemetry.
- Free keys see the last 7 days. Older data needs a paid tier; the tool result says so when a request is out of window.
