import { readFileSync } from "node:fs";
import type { Writable } from "node:stream";
import type { AppContext } from "../core/context.js";
import { openBrowserChecked } from "../core/browser.js";
import { ProjectMemoryClient, ProjectMemoryWorkingCopy, graphDiff, type SignedReceipt } from "../core/project_memory.js";

export interface ProjectMemoryOptions {
  project?: string; offline?: boolean; noOpen?: boolean; message?: string;
  graphFile?: string; evidenceFile?: string; out?: Writable;
}

export function normalizeMemoryArguments(argv: string[]): string[] {
  const args = [...argv];
  if (args[0] === "-m" || args[0] === "m") args[0] = "memory";
  if (args[0] !== "memory") return args;
  const actions = args.slice(1).filter(x => ["--push", "--pull", "--commit", "--graph"].includes(x));
  if (actions.length > 1) throw new Error("Choose exactly one Project Memory action");
  if (actions[0] && args[1] === actions[0]) args[1] = actions[0].slice(2);
  // -m inside this command is a message flag; other commands are untouched.
  for (let i = 2; i < args.length; i++) if (args[i] === "-m") args[i] = "--message";
  return args;
}

export async function cmdProjectMemory(ctx: AppContext, argv: string[], options: ProjectMemoryOptions = {}): Promise<number> {
  const out = options.out ?? process.stdout;
  const project = options.project ?? process.env["AETHER_PROJECT_ID"];
  try {
    if (!project) throw new Error("project_binding_required");
    const copy = new ProjectMemoryWorkingCopy(project, ctx.flags.cwd);
    const client = new ProjectMemoryClient(ctx.api, copy);
    const command = argv[0] ?? "status";
    const offline = options.offline || ctx.flags.local;
    if (offline && ["init", "push", "pull", "sync", "show"].includes(command)) throw new Error("project_memory_offline");
    const fromFile = (file?: string): unknown => {
      if (!file) throw new Error("project_memory_graph_file_required");
      const content = readFileSync(file);
      if (content.length > 32_000_000) throw new Error("project_memory_pack_limit");
      return JSON.parse(content.toString("utf8"));
    };
    let result: unknown;
    if (command === "init") result = await client.init();
    else if (command === "status") result = await client.status(offline);
    else if (command === "diff") { const state = client.requireState(); result = graphDiff(state.base_graph, state.graph); }
    else if (command === "stage" || command === "reconcile") {
      const evidence = options.evidenceFile ? fromFile(options.evidenceFile) as SignedReceipt[] : [];
      const graph = fromFile(options.graphFile ?? argv[1]);
      result = command === "stage" ? client.stage(graph, evidence) : client.reconcile(graph, evidence);
    } else if (command === "commit") result = client.commit(options.message ?? "");
    else if (command === "push") result = await client.push();
    else if (command === "pull") result = await client.pull();
    else if (command === "sync") {
      result = await client.pull();
      const state = client.requireState();
      if (state.candidate && !state.conflicts.length) result = await client.push();
    } else if (command === "log") result = await client.log(offline);
    else if (command === "show") result = await client.show(argv[1] ?? "");
    else if (command === "graph") {
      const state = client.requireState();
      const url = offline ? null : await client.open();
      result = { project_id: project, graph_id: state.base.graph_id, revision: state.base.revision,
        checksum: state.base.checksum, nodes: state.graph.nodes.length, edges: state.graph.edges.length,
        partial: state.graph.partial, open_url: url };
      if (url && !options.noOpen && !ctx.flags.json && process.stdout.isTTY) openBrowserChecked(url);
    } else throw new Error("usage: aether memory init|status|diff|stage|commit|push|pull|sync|log|show|graph|reconcile");
    out.write(JSON.stringify({ schema_version: "ProjectMemoryCliV1", ok: true, project_id: project, result }, null, ctx.flags.json ? undefined : 2) + "\n");
    return 0;
  } catch (error) {
    const detail = error instanceof Error ? ("code" in error ? String(error.code) : error.message) : "";
    const code = /^(?:project_memory_|project_binding_)[a-z_]+$/.test(detail) ? detail : "project_memory_storage_unavailable";
    out.write(JSON.stringify({ schema_version: "ProjectMemoryCliV1", ok: false, project_id: project ?? null, error: code }) + "\n");
    return 2;
  }
}
