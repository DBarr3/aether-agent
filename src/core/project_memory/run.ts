import type { AppContext } from "../context.js";
import { buildGraph, repositoryRoot } from "./builder.js";
import { ProjectStore } from "./store.js";
import { resolveMemoryBinding } from "../../commands/project_memory.js";
import { memoryApi } from "./network.js";
import { memoryFooter } from "./receipt.js";
import { push } from "./sync.js";

/** Host pins a local revision once; subsequent commits cannot rewrite it. */
export function pinMemory(ctx: AppContext): Readonly<{ project_id: string; commit_id: string | null; graph_revision: number | null; graph_checksum: string | null }> | null {
  try {
    const binding = resolveMemoryBinding(ctx);
    if (!binding) return null;
    const store = new ProjectStore(binding), state = store.state();
    // Revisions belong to a specific server commit, never to its local child.
    const revision = state.head && state.head === state.remote.commit_id ? state.remote.revision : null;
    return Object.freeze({ project_id: binding.project_id, commit_id: state.head, graph_revision: revision,
      graph_checksum: state.head ? store.manifest(state.head).graph_checksum : null });
  } catch { return null; }
}
export async function completeMemory(ctx: AppContext, pinned: ReturnType<typeof pinMemory>, succeeded: boolean): Promise<string> {
  try {
    if (!succeeded) return "Memory  not committed (coding run did not pass verification)";
    const root = repositoryRoot(ctx.flags.cwd), binding = resolveMemoryBinding(ctx);
    if (binding?.policy?.auto_commit && binding.policy.local_builder && pinned && pinned.project_id === binding.project_id) {
      const store = new ProjectStore(binding);
      await store.locked(async () => {
        const state = store.state();
        if (state.head !== pinned.commit_id || state.conflict || state.index) return;
        const built = buildGraph(root, binding.project_id);
        const committed = store.commit(built.graph, built.sourceSha, "Verified coding run", { git: [built.sourceSha] });
        if (committed && binding.policy?.auto_push && process.env["AETHER_HOST_SURFACE"] === "desktop" && !ctx.flags.local) {
          await push(store, memoryApi(ctx));
        }
      });
    }
    return await memoryFooter(ctx);
  } catch { return "Memory  not committed remotely; local work is preserved"; }
}
