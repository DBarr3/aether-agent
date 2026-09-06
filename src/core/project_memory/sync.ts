import type { ApiClient } from "../transport.js";
import { buildGraph, repositoryName } from "./builder.js";
import { join } from "node:path";
import { mergeGraphs } from "./merge.js";
import { digest, graphId, identifier, requireMemory, validateGraph, validateManifest, validateReceipt, type Binding, type Graph, type Manifest, type Receipt, type Remote } from "./contract.js";
import { atomicWrite, ProjectStore } from "./store.js";

export interface Head extends Remote {
  schema_version: 1; author_principal_id: string;
  binding: { repository_full_name: string; repository_numeric_id: number; binding_digest: string };
  policy?: Binding["policy"];
}
interface Snapshot { project_id: string; graph_id: string; manifest: Manifest; graph: Graph; revision: number; receipt: Receipt; open_url: string }
export function memoryPath(project: string, suffix: string): string {
  identifier(project, "prj");
  return `/gateway/projects/${project}/memory/${suffix}`;
}
export async function remoteHead(api: ApiClient, project: string, root: string): Promise<Head> {
  const head = await api.getJson(memoryPath(project, "head")) as Head;
  requireMemory(head.schema_version === 1 && head.project_id === project && head.graph_id === graphId(project));
  requireMemory(head.binding?.repository_full_name?.toLowerCase() === repositoryName(root), "project_binding_required");
  requireMemory(Number.isSafeInteger(head.binding.repository_numeric_id) && head.binding.repository_numeric_id > 0 && typeof head.binding.binding_digest === "string");
  requireMemory(typeof head.author_principal_id === "string" && head.author_principal_id.length > 0);
  requireMemory(Number.isSafeInteger(head.revision) && head.revision >= 0 && ((head.revision === 0 && head.commit_id === null && head.graph_checksum === null) || (head.revision > 0 && typeof head.commit_id === "string" && typeof head.graph_checksum === "string")));
  return head;
}
export function bindingFromHead(head: Head, root: string): Binding {
  return { project_id: head.project_id, graph_id: head.graph_id, author_principal_id: head.author_principal_id, root,
    repository_full_name: head.binding.repository_full_name, repository_numeric_id: head.binding.repository_numeric_id,
    binding_digest: head.binding.binding_digest, ...(head.policy ? { policy: {
      auto_commit: head.policy.auto_commit === true, auto_push: head.policy.auto_push === true, local_builder: head.policy.local_builder === true,
    } } : {}) };
}
function track(head: Remote): Remote {
  return { project_id: head.project_id, graph_id: head.graph_id, commit_id: head.commit_id, revision: head.revision, graph_checksum: head.graph_checksum };
}
async function verifiedHead(store: ProjectStore, api: ApiClient): Promise<Head> {
  const head = await remoteHead(api, store.binding.project_id, store.binding.root);
  requireMemory(head.binding.repository_numeric_id === store.binding.repository_numeric_id && head.binding.binding_digest === store.binding.binding_digest && head.author_principal_id === store.binding.author_principal_id, "project_binding_required");
  return head;
}
export async function fetchSnapshot(store: ProjectStore, api: ApiClient, commit: string): Promise<Snapshot> {
  identifier(commit, "memc");
  const value = await api.getJson(memoryPath(store.binding.project_id, `packs?commit_id=${encodeURIComponent(commit)}`)) as Snapshot;
  requireMemory(value.project_id === store.binding.project_id && value.graph_id === store.binding.graph_id);
  validateManifest(value.manifest, store.binding.project_id);
  requireMemory(value.manifest.commit_id === commit);
  validateGraph(value.graph, store.binding.project_id);
  requireMemory(digest(value.graph) === value.manifest.graph_checksum);
  validateReceipt(value.receipt, value.manifest, value.revision);
  store.object(value.graph);
  store.putManifest(value.manifest);
  return value;
}
export async function pull(store: ProjectStore, api: ApiClient): Promise<string> {
  const remote = await verifiedHead(store, api);
  const state = store.state();
  if (!remote.commit_id) {
    requireMemory(state.remote.commit_id === null, "project_memory_integrity_failure");
    return "uninitialized";
  }
  if (remote.commit_id === state.remote.commit_id && remote.revision === state.remote.revision && remote.graph_checksum === state.remote.graph_checksum) {
    return "unchanged";
  }
  // Fetch before deciding whether refs can move; verified objects survive a
  // conflict and are available to diff/reconcile without losing local work.
  const snapshot = await fetchSnapshot(store, api, remote.commit_id);
  requireMemory(snapshot.revision === remote.revision && snapshot.manifest.graph_checksum === remote.graph_checksum);
  let cursor: string | null = remote.commit_id;
  let steps = 0;
  while (cursor && cursor !== state.head && cursor !== state.remote.commit_id) {
    requireMemory(++steps <= 1000, "project_memory_history_limit");
    if (!store.hasCommit(cursor)) await fetchSnapshot(store, api, cursor);
    cursor = store.manifest(cursor).parent_commit_ids[0] ?? null;
  }
  requireMemory(!state.index, "project_memory_dirty");
  if (!(state.head === remote.commit_id || (state.head === state.remote.commit_id && cursor === state.head))) {
    let entityIds: string[] = [];
    if (state.head && state.remote.commit_id && cursor === state.remote.commit_id) {
      const localGraph = store.graph(store.manifest(state.head).graph_checksum);
      const baseGraph = store.graph(store.manifest(state.remote.commit_id).graph_checksum);
      const built = buildGraph(store.binding.root, store.binding.project_id);
      // Source selection must agree before an automatic merge. A Git-tree
      // change needs a human choice; never silently reintroduce stale files.
      if (localGraph.source_tree_sha === snapshot.graph.source_tree_sha && built.graph.source_tree_sha === localGraph.source_tree_sha) {
        const merged = mergeGraphs(baseGraph, localGraph, snapshot.graph, built.graph);
        entityIds = merged.conflicts;
        if (!entityIds.length) {
          validateGraph(merged.graph, store.binding.project_id);
          atomicWrite(join(store.workspace, `reconciled-${state.head}.json`), state);
          const base = { ...state, head: remote.commit_id, remote: track(remote), receipt: snapshot.receipt, conflict: null };
          const manifest = store.commit(merged.graph, built.sourceSha, "Reconcile project memory", { memory: [state.head] }, base);
          if (!manifest) store.save(base);
          return manifest ? "local" : "unchanged";
        }
      }
    }
    store.save({ ...state, conflict: { local_head: state.head, actual_head: track(remote), common_ancestor: cursor, entity_ids: entityIds } });
    requireMemory(false, "project_memory_head_conflict");
  }
  store.save({ ...state, head: remote.commit_id, remote: track(remote), receipt: snapshot.receipt, conflict: null });
  return state.head === remote.commit_id ? "unchanged" : "pushed";
}
export async function push(store: ProjectStore, api: ApiClient): Promise<string> {
  let state = store.state();
  requireMemory(!state.index, "project_memory_dirty");
  const remote = await verifiedHead(store, api);
  if (remote.commit_id === state.head && state.head) {
    // Recover a lost finalization response using an authenticated exact commit.
    const snapshot = await fetchSnapshot(store, api, state.head);
    requireMemory(snapshot.revision === remote.revision && snapshot.manifest.graph_checksum === remote.graph_checksum);
    store.save({ ...state, remote: track(remote), receipt: snapshot.receipt });
    return "unchanged";
  }
  if (remote.commit_id && remote.commit_id !== state.remote.commit_id) {
    const pendingIds = store.history(state.head, state.remote.commit_id).reverse();
    const acceptedIndex = pendingIds.findIndex((m) => m.commit_id === remote.commit_id);
    if (acceptedIndex >= 0) {
      const snapshot = await fetchSnapshot(store, api, remote.commit_id);
      requireMemory(snapshot.revision === state.remote.revision + acceptedIndex + 1 && snapshot.revision === remote.revision && snapshot.manifest.graph_checksum === remote.graph_checksum);
      state = { ...state, remote: track(remote), receipt: snapshot.receipt };
      store.save(state);
    }
  }
  if (!(remote.commit_id === state.remote.commit_id && remote.revision === state.remote.revision && remote.graph_checksum === state.remote.graph_checksum)) {
    store.save({ ...state, conflict: { local_head: state.head, actual_head: track(remote), common_ancestor: state.remote.commit_id, entity_ids: [] } });
    requireMemory(false, "project_memory_head_conflict");
  }
  const pending = store.history(state.head, state.remote.commit_id).reverse();
  for (const manifest of pending) {
    const graph = store.graph(manifest.root_object_digest);
    await api.postJson(memoryPath(store.binding.project_id, "packs"), { objects: [{ digest: manifest.root_object_digest, value: graph }] });
    const result = await api.postJson(memoryPath(store.binding.project_id, "commits"), {
      commit_manifest: manifest, expected_head_commit_id: state.remote.commit_id,
      expected_revision: state.remote.revision, expected_graph_checksum: state.remote.graph_checksum,
      idempotency_key: manifest.commit_id,
    }) as { receipt: Receipt };
    validateReceipt(result.receipt, manifest, state.remote.revision + 1);
    state = { ...state, remote: track(result.receipt), receipt: result.receipt, conflict: null };
    store.save(state);
  }
  return pending.length ? "pushed" : "unchanged";
}
export function graphDiff(left: Graph, right: Graph): { added: string[]; changed: string[]; removed: string[] } {
  const a = new Map([...left.nodes, ...left.edges].map((e) => [e.id, digest(e)]));
  const b = new Map([...right.nodes, ...right.edges].map((e) => [e.id, digest(e)]));
  return { added: [...b.keys()].filter((id) => !a.has(id)), changed: [...b.keys()].filter((id) => a.has(id) && a.get(id) !== b.get(id)), removed: [...a.keys()].filter((id) => !b.has(id)) };
}
