#!/usr/bin/env node
/**
 * stdio MCP server exposing the ThreatCluster public API.
 * Run as `threatcluster-mcp` or `npx -y threatcluster-mcp`. The server name is
 * `threatcluster`; tools and prompts come verbatim from tools.json.
 */
import { readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema, GetPromptRequestSchema, ListPromptsRequestSchema, ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  ApiError, ENV_API_BASE, ENV_API_KEY, FREE_KEY_URL, ThreatClusterClient, resolveApiKey, scrubKeyShapes,
} from "./client.js";
import { ToolInputError, ToolRunner, loadSpec, promptSpecs, renderPrompt, toolSpec, toolSpecs, validateArgs } from "./tools.js";

export const VERSION: string = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version || "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

const ANNOTATIONS = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true };

function errorResult(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true };
}

export function buildServer(client: ThreatClusterClient): Server {
  const spec = loadSpec();
  const runner = new ToolRunner(client);
  const server = new Server({ name: spec.server.name, version: VERSION },
    { capabilities: { tools: {}, prompts: {} }, instructions: spec.server.instructions });

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolSpecs().map((t) => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema,
      annotations: ANNOTATIONS })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const t = toolSpec(name);
    if (!t) return errorResult(`unknown tool '${name}'`);
    let args: Record<string, unknown>;
    try {
      args = validateArgs(t.inputSchema, req.params.arguments);
    } catch (e: any) {
      return errorResult(`invalid arguments for ${name}: ${client.redact(scrubKeyShapes(String(e?.message || e)))}`);
    }
    if (name !== "api_budget" && !client.hasKey) {
      return errorResult(`No ThreatCluster API key is configured. Set ${ENV_API_KEY} (free key: ${FREE_KEY_URL}) ` +
        "or run `tc auth login` with the ThreatCluster CLI.");
    }
    let result: Record<string, unknown>;
    try {
      result = await runner.run(name, args);
    } catch (e: any) {
      if (e instanceof ApiError) return errorResult(client.redact(e.toText()));
      if (e instanceof ToolInputError) return errorResult(`invalid arguments for ${name}: ${client.redact(e.message)}`);
      const msg = client.redact(scrubKeyShapes(`${e?.name || "Error"}: ${e?.message || e}`));
      console.error(`threatcluster_mcp: tool ${name} failed: ${msg}`);
      return errorResult(`${name} failed: ${msg}`);
    }
    return { content: [{ type: "text" as const, text: JSON.stringify(result) }], structuredContent: result };
  });

  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: promptSpecs().map((p) => ({ name: p.name, title: p.title, description: p.description,
      arguments: p.arguments.map((a) => ({ name: a.name, description: a.description, required: Boolean(a.required) })) })),
  }));

  server.setRequestHandler(GetPromptRequestSchema, async (req) => {
    const p = promptSpecs().find((x) => x.name === req.params.name);
    if (!p) throw new Error(`unknown prompt '${req.params.name}'`);
    return { description: p.description,
      messages: [{ role: "user" as const, content: { type: "text" as const, text: client.redact(renderPrompt(p, req.params.arguments)) } }] };
  });

  return server;
}

function check(client: ThreatClusterClient, source: string): number {
  // Never print the key. Only where it came from and where it will be sent.
  process.stderr.write(`threatcluster-mcp ${VERSION}\n`);
  process.stderr.write(`api base: ${client.base}  (${ENV_API_BASE})\n`);
  process.stderr.write(`api key : ${client.hasKey ? "configured" : "MISSING"} (source: ${source})\n`);
  process.stderr.write(`tools   : ${toolSpecs().map((t) => t.name).join(", ")}\n`);
  if (!client.hasKey) {
    process.stderr.write(`set ${ENV_API_KEY}; free keys at ${FREE_KEY_URL}\n`);
    return 1;
  }
  return 0;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  if (argv.includes("--version") || argv.includes("-V")) {
    process.stdout.write(`threatcluster-mcp ${VERSION}\n`);
    return 0;
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    process.stdout.write("usage: threatcluster-mcp [--check] [--version]\n" +
      "MCP server (stdio) for the ThreatCluster API. Configure THREATCLUSTER_API_KEY.\n");
    return 0;
  }
  const { key, source } = resolveApiKey();
  const client = new ThreatClusterClient(key, { keySource: source, userAgent: `threatcluster-mcp/${VERSION} (node)` });
  if (argv.includes("--check")) return check(client, source);
  if (!key) {
    console.error(`threatcluster_mcp: no API key found (${ENV_API_KEY} unset, no tc-cli credential); ` +
      `tools will return an auth error. Free key: ${FREE_KEY_URL}`);
  }
  const server = buildServer(client);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  await new Promise<void>((resolve) => {
    transport.onclose = () => resolve();
    process.stdin.on("end", () => resolve());
  });
  await server.close().catch(() => undefined);
  return 0;
}

const isDirectRun = (() => {
  try {
    const argv1 = process.argv[1] ? new URL(`file://${process.argv[1]}`).pathname : "";
    return argv1 !== "" && (import.meta.url.endsWith(argv1) || argv1.endsWith("threatcluster-mcp"));
  } catch {
    return false;
  }
})();

if (isDirectRun) {
  main().then((code) => process.exit(code)).catch((e) => {
    process.stderr.write(`threatcluster_mcp: ${scrubKeyShapes(String(e?.message || e))}\n`);
    process.exit(1);
  });
}
