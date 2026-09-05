# Cursor one-click install

Cursor accepts an install deeplink of the form
`cursor://anysphere.cursor-deeplink/mcp/install?name=<server>&config=<base64 JSON>` where the JSON is the
server entry that would sit under `mcpServers` in `mcp.json`.

Config encoded below (the user replaces `YOUR_THREATCLUSTER_API_KEY` in Cursor's MCP settings after install):

```json
{"command":"npx","args":["-y","threatcluster-mcp"],"env":{"THREATCLUSTER_API_KEY":"YOUR_THREATCLUSTER_API_KEY"}}
```

Deeplink:

```
cursor://anysphere.cursor-deeplink/mcp/install?name=threatcluster&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInRocmVhdGNsdXN0ZXItbWNwIl0sImVudiI6eyJUSFJFQVRDTFVTVEVSX0FQSV9LRVkiOiJZT1VSX1RIUkVBVENMVVNURVJfQVBJX0tFWSJ9fQ==
```

Markdown badge for the README / site (Cursor's official badge asset):

```markdown
[![Install in Cursor](https://cursor.com/deeplink/mcp-install-dark.svg)](cursor://anysphere.cursor-deeplink/mcp/install?name=threatcluster&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsInRocmVhdGNsdXN0ZXItbWNwIl0sImVudiI6eyJUSFJFQVRDTFVTVEVSX0FQSV9LRVkiOiJZT1VSX1RIUkVBVENMVVNURVJfQVBJX0tFWSJ9fQ==)
```

Regenerate after any change to the config:

```bash
python3 -c "import base64,json;print(base64.b64encode(json.dumps({'command':'npx','args':['-y','threatcluster-mcp'],'env':{'THREATCLUSTER_API_KEY':'YOUR_THREATCLUSTER_API_KEY'}},separators=(',',':')).encode()).decode())"
```

Cursor directory listing: https://cursor.com/directory (submit via the form linked from the directory page;
needs the GitHub repo URL, the deeplink above, a logo and a one-paragraph description — reuse mcp-so.md).
