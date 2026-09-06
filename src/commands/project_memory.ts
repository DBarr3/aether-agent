import type { Writable } from "node:stream";
import type { AppContext } from "../core/context.js";
import { HttpError } from "../core/errors.js";
import { memoryApi } from "../core/project_memory/network.js";
import type { CommandFlags } from "../core/command_dispatch.js";
import { openBrowserAwaitLaunch } from "../core/browser.js";
import { buildGraph, git, repositoryName, repositoryRoot } from "../core/project_memory/builder.js";
import { canonical, requireMemory, ProjectMemoryError, type Binding, type Manifest } from "../core/project_memory/contract.js";
import { cachedBinding, ProjectStore } from "../core/project_memory/store.js";
import { bindingFromHead, fetchSnapshot, graphDiff, memoryPath, pull, push, remoteHead } from "../core/project_memory/sync.js";

export interface ProjectMemoryOptions {
  project?: string; offline?: boolean; noOpen?: boolean; message?: string;
  linkGit?: string; linkPr?: string; push?: boolean; against?: string; out?: Writable;
}
export function projectMemoryOptions(flags: CommandFlags): ProjectMemoryOptions {
  return { project: flags.str("project"), offline: flags.bool("offline"), noOpen: flags.bool("no-open"),
    message: flags.str("message"), linkGit: flags.str("link-git"), linkPr: flags.str("link-pr"),
    push: flags.bool("push"), against: flags.str("against") };
}
export function normalizeMemoryArgs(argv: string[]): string[] {
  const args = [...argv];
  if (args[0] === "--memory-graph") return ["memory", "graph", ...args.slice(1)];
  if (args[0] === "-m") args[0] = "memory";
  if (args[0] === "memory" || args[0] === "m") {
    const actions = new Set(["--push", "--pull", "--commit", "--graph"]);
    if (actions.has(args[1] ?? "")) {
      requireMemory(!args.slice(2).some((a) => actions.has(a)), "project_memory_invalid_action_flags");
      args[1] = args[1]!.slice(2);
    }
  }
  return args;
}
function resolveBinding(ctx: AppContext, options: ProjectMemoryOptions): Binding | null {
  const root = repositoryRoot(ctx.flags.cwd);
  const binding = cachedBinding(root);
  if (binding) {
    requireMemory(binding.repository_full_name.toLowerCase() === repositoryName(root), "project_binding_required");
    const expectedOwner = process.env["AETHER_PROJECT_MEMORY_OWNER_ID"];
    if (expectedOwner) requireMemory(binding.author_principal_id === expectedOwner, "project_binding_required");
  }
  const project = options.project ?? process.env["AETHER_PROJECT_ID"];
  if (project && binding) requireMemory(binding.project_id === project, "project_binding_required");
  return binding;
}
export function projectStatus(ctx: AppContext, options: ProjectMemoryOptions = {}): Record<string, unknown> {
  try {
    const binding = resolveBinding(ctx, options);
    if (!binding) return { schema_version: 1, state: "uninitialized", code: "project_binding_required" };
    const store = new ProjectStore(binding);
    const state = store.state();
    return { schema_version: 1, project_id: binding.project_id, graph_id: binding.graph_id,
      local_head: state.head, remote_head: state.remote.commit_id, revision: state.remote.revision,
      graph_checksum: state.head ? store.manifest(state.head).graph_checksum : null,
      state: state.conflict ? "conflicted" : state.index ? "dirty" : state.head !== state.remote.commit_id ? "local" : state.head ? "synchronized" : "uninitialized",
      conflict: state.conflict ?? null,
      remote_checked: false, receipt: state.receipt, open_url: null };
  } catch (error) {
    return { schema_version: 1, state: "blocked", code: error instanceof ProjectMemoryError ? error.code : "project_binding_required" };
  }
}
function safeLink(value: unknown, project: string, commit: string): string {
  requireMemory(typeof value === "string");
  const url = new URL(value);
  requireMemory(["https:", "http:"].includes(url.protocol) && !url.username && !url.password && !url.hash);
  requireMemory(url.searchParams.get("project") === project && url.searchParams.get("memoryCommit") === commit);
  for (const key of url.searchParams.keys()) requireMemory(["project", "memoryCommit", "compareMemoryCommit"].includes(key));
  return url.href;
}
export async function cmdProjectMemory(ctx: AppContext, argv: string[], options: ProjectMemoryOptions = {}): Promise<number> {
  const out = options.out ?? process.stdout;
  const sub = argv[0] ?? "status";
  try {
    ctx = { ...ctx, api: memoryApi(ctx) };
    if (sub === "status") { out.write(canonical(projectStatus(ctx, options)) + "\n"); return 0; }
    const root = repositoryRoot(ctx.flags.cwd);
    let binding = resolveBinding(ctx, options);
    if (sub === "init" && !options.offline) {
      const project = options.project ?? process.env["AETHER_PROJECT_ID"] ?? binding?.project_id;
      requireMemory(project, "project_binding_required");
      binding = bindingFromHead(await remoteHead(ctx.api, project, root), root);
    }
    requireMemory(binding, "project_binding_required");
    const store = new ProjectStore(binding);
    const result: Record<string, unknown> = await store.locked(async () => {
      let state = "unchanged";
      let selected: Manifest | null = null;
      let extra: Record<string, unknown> = {};
      if (sub === "init") {
        if (!options.offline) state = await pull(store, ctx.api);
        if (!store.state().head) {
          requireMemory(process.env["AETHER_PROJECT_MEMORY_LOCAL_BUILDER_ENABLED"] !== "0", "project_memory_disabled");
          requireMemory(binding.policy?.local_builder !== false, "project_memory_disabled");
          const built = buildGraph(root, binding.project_id);
          selected = store.commit(built.graph, built.sourceSha, options.message ?? "Project Genesis");
          state = "local";
        }
      } else if (sub === "commit") {
        const built = buildGraph(root, binding.project_id);
        const gitLinks = options.linkGit ? [git(root, ["rev-parse", "--verify", "--end-of-options", `${options.linkGit}^{commit}`]).trim()] : [];
        const prs = options.linkPr ? [Number(options.linkPr)] : [];
        requireMemory(prs.every((n) => Number.isSafeInteger(n) && n > 0), "project_memory_invalid_pr");
        selected = store.commit(built.graph, built.sourceSha, options.message ?? "", { git: gitLinks, prs });
        state = selected ? "local" : "unchanged";
      } else if (["push", "pull", "sync"].includes(sub)) {
        requireMemory(!options.offline, "project_memory_offline");
        if (sub !== "push") state = await pull(store, ctx.api);
        if (sub !== "pull") state = await push(store, ctx.api);
      } else if (sub === "log") {
        extra = { commits: store.history().map((m) => ({ ...m, state: store.state().remote.commit_id && store.history(store.state().remote.commit_id).some((r) => r.commit_id === m.commit_id) ? "pushed" : "local" })) };
      } else if (sub === "show") {
        requireMemory(argv[1], "project_memory_commit_required");
        selected = store.manifest(argv[1]);
        extra = { manifest: selected };
      } else if (sub === "diff") {
        const local = store.state();
        requireMemory(local.head, "project_memory_commit_required");
        const base = store.graph(store.manifest(local.head).graph_checksum);
        if (options.against === "remote") {
          requireMemory(!options.offline, "project_memory_offline");
          const remote = await remoteHead(ctx.api, binding.project_id, root);
          requireMemory(remote.commit_id, "project_memory_commit_required");
          extra = graphDiff(base, (await fetchSnapshot(store, ctx.api, remote.commit_id)).graph);
        } else extra = graphDiff(base, buildGraph(root, binding.project_id).graph);
      } else if (sub === "graph" || sub === "reconcile") {
        requireMemory(!options.offline, "project_memory_offline");
        if (sub === "reconcile") {
          try { state = await pull(store, ctx.api); } catch (error) {
            if (!(error instanceof ProjectMemoryError) || error.code !== "project_memory_head_conflict") throw error;
            state = "conflicted";
          }
        }
        const local = store.state();
        if (sub === "reconcile" && !local.conflict) return { ...projectStatus(ctx, options), state };
        const selectedId = argv[1] ?? (sub === "reconcile" && local.conflict ? local.conflict.actual_head.commit_id : local.head);
        requireMemory(selectedId, "project_memory_not_pushed");
        const compare = sub === "reconcile" ? local.conflict?.common_ancestor : null;
        const value = await ctx.api.getJson(memoryPath(binding.project_id, `open?commit_id=${encodeURIComponent(selectedId)}${compare ? `&compare_commit_id=${encodeURIComponent(compare)}` : ""}`)) as { project_id: string; commit_id: string; open_url: string };
        requireMemory(value.project_id === binding.project_id && value.commit_id === selectedId);
        const url = safeLink(value.open_url, binding.project_id, selectedId);
        extra = { open_url: url, commit_id: selectedId };
        if (!options.noOpen && !ctx.flags.json && process.stdout.isTTY) await openBrowserAwaitLaunch(url);
      } else throw new ProjectMemoryError("project_memory_unknown_command");
      const approvedAutoPush = binding.policy?.auto_push === true && process.env["AETHER_HOST_SURFACE"] === "desktop" && !options.offline;
      if ((options.push || approvedAutoPush) && ["init", "commit"].includes(sub)) {
        requireMemory(!options.offline, "project_memory_offline");
        state = await push(store, ctx.api);
      }
      return { ...projectStatus(ctx, options), state, ...(selected ? { commit_id: selected.commit_id } : {}), ...extra };
    });
    if (ctx.flags.json) out.write(canonical(result) + "\n");
    else if (result["open_url"]) out.write(String(result["open_url"]) + "\n");
    else if (Array.isArray(result["commits"])) {
      for (const m of result["commits"] as (Manifest & { state: string })[]) out.write(`${m.commit_id}  ${m.message}  ${m.state}\n`);
    } else out.write(`Project memory: ${result["state"]}${result["commit_id"] ? " " + result["commit_id"] : ""}\n${["diff", "show"].includes(sub) ? canonical(result) + "\n" : ""}`);
    return result["state"] === "conflicted" ? 2 : 0;
  } catch (error) {
    const detail = error instanceof HttpError ? (error.body as { detail?: { code?: unknown } })?.detail?.code : null;
    const code = error instanceof ProjectMemoryError ? error.code : typeof detail === "string" && /^(project_memory_[a-z_]+|authentication_required|project_binding_required)$/.test(detail) ? detail : "project_memory_operation_failed";
    const state = code === "project_memory_head_conflict" ? "conflicted" : "not committed";
    out.write(ctx.flags.json ? canonical({ schema_version: 1, state, code }) + "\n" : `Project memory: ${state} (${code}). Local commits remain available.\n`);
    return 2;
  }
}
