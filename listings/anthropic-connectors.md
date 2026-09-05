# Claude connectors directory (claude.ai) — phase 2, not built

What is here today is a **stdio** server: it runs on the user's machine (Claude Desktop, Claude Code, Cursor,
VS Code) and holds the user's own API key. That is deliberately the simplest, most auditable shape.

The Claude connectors directory (claude.ai → Settings → Connectors → *Browse connectors*, and the "Add custom
connector" flow) lists **remote** servers reached from Anthropic's cloud. A listing needs:

1. **Streamable HTTP transport** at a public HTTPS URL (e.g. `https://mcp.threatcluster.io/mcp`), stateless or
   with session ids, CORS not required (server-to-server).
2. **OAuth 2.1 authorization** per the MCP auth spec: the server advertises
   `/.well-known/oauth-protected-resource`, points at an authorization server that supports **dynamic client
   registration** (RFC 7591), PKCE, and issues tokens the MCP server can verify. ThreatCluster's Auth0 tenant
   can be the authorization server (enable DCR, add the MCP server as an API/audience); the resulting access
   token maps to the user's ThreatCluster account and tier, so no API key is ever typed into Claude.
3. **Tool safety metadata**: read-only annotations (already set), clear tool descriptions (already the case),
   and a privacy policy + terms URL (https://threatcluster.io/privacy, /terms).
4. **Directory submission**: Anthropic's form for the connectors directory (from the Claude help centre /
   developer platform, "Submit a connector"), with: company name, logo (SVG/PNG), server URL, OAuth details,
   a support contact, a description, and a demo account for review.

Implementation plan (reuses this repo unchanged for the tools):

- Add a `remote/` package (Python, `mcp.server.streamable_http`) that mounts the same `ToolRunner` behind
  Streamable HTTP, resolves the caller from the OAuth bearer (Auth0 JWT → user → mint an internal
  `tc_agent_` key or bearer with `mint_agent_bearer`, scoped to the user's tier) and injects it into
  `ThreatClusterClient` per request. Budget/rate limits then apply per user exactly as for direct API use.
- Deploy on the API host under `mcp.threatcluster.io` (App Platform component), with the origin-secret /
  proxy trust settings the public API already uses.
- Add `/.well-known/oauth-protected-resource` and register an Auth0 API with DCR enabled.
- Only then submit to the connectors directory; also list the remote URL on Smithery (hosted) and in
  `listings/server.json` as a `remotes` entry.

Until then, claude.ai users can still use the stdio server through Claude Desktop, and the API-key based
`Add custom connector` flow is not applicable (custom connectors must also be remote MCP servers).
