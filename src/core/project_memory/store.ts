import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { randomUUID } from "node:crypto";
import { configDir } from "../config.js";
import { graphContent, withLineage } from "./lineage.js";
import { MAX_BYTES, canonical, digest, graphId, hash, identifier, requireMemory, validateGraph, validateManifest, validateReceipt, type Binding, type Graph, type Manifest, type Receipt, type Remote } from "./contract.js";

export interface State {
  schema_version: 1; binding: Binding; head: string | null; remote: Remote;
  index: string | null; receipt: Receipt | null;
  conflict?: { local_head: string | null; actual_head: Remote; common_ancestor: string | null; entity_ids: string[] } | null;
}
export function atomicWrite(path: string, value: unknown): void {
  const temporary = `${path}.${randomUUID()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, canonical(value)); fsyncSync(fd); } finally { closeSync(fd); }
  try { renameSync(temporary, path); } finally { if (existsSync(temporary)) unlinkSync(temporary); }
  if (process.platform !== "win32") {
    const directory = openSync(dirname(path), "r");
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }
}
function boundedRead(path: string): string {
  requireMemory(statSync(path).size <= MAX_BYTES, "project_memory_integrity_failure");
  return readFileSync(path, "utf8");
}
export function bindingPath(root: string): string { return join(configDir(), "project-memory-bindings", hash(root) + ".json"); }
export function cachedBinding(root: string): Binding | null {
  const file = bindingPath(root);
  if (!existsSync(file)) return null;
  const binding = JSON.parse(boundedRead(file)) as Binding;
  identifier(binding.project_id, "prj");
  requireMemory(binding.root === root && binding.graph_id === graphId(binding.project_id), "project_binding_required");
  return binding;
}
export class ProjectStore {
  readonly base: string;
  readonly workspace: string;
  constructor(readonly binding: Binding, private readonly data = configDir()) {
    identifier(binding.project_id, "prj");
    requireMemory(binding.graph_id === graphId(binding.project_id));
    this.base = join(data, "projects", binding.project_id, "memory");
    this.workspace = join(this.base, "worktrees", hash(binding.root));
  }
  initialize(): void {
    for (const path of [this.base, join(this.base, "objects"), join(this.base, "commits"), this.workspace, join(this.data, "project-memory-bindings")]) mkdirSync(path, { recursive: true, mode: 0o700 });
    const file = join(this.data, "project-memory-bindings", hash(this.binding.root) + ".json");
    atomicWrite(file, this.binding);
  }
  async locked<T>(fn: () => T | Promise<T>): Promise<T> {
    this.initialize();
    const lock = join(this.base, "operation.lock");
    try { mkdirSync(lock, { mode: 0o700 }); } catch { requireMemory(false, "project_memory_locked"); }
    try { return await fn(); } finally { rmdirSync(lock); }
  }
  state(): State {
    const file = join(this.workspace, "state.json");
    if (!existsSync(file)) return { schema_version: 1, binding: this.binding, head: null, index: null, receipt: null,
      remote: { project_id: this.binding.project_id, graph_id: this.binding.graph_id, commit_id: null, graph_checksum: null, revision: 0 } };
    try {
      const value = JSON.parse(boundedRead(file)) as State;
      requireMemory(value.schema_version === 1 && value.binding.root === this.binding.root && value.binding.project_id === this.binding.project_id);
      requireMemory(value.remote.project_id === this.binding.project_id && value.remote.graph_id === this.binding.graph_id && Number.isSafeInteger(value.remote.revision) && value.remote.revision >= 0);
      if (value.head) this.manifest(value.head);
      if (value.index) this.graph(value.index);
      if (value.remote.commit_id) {
        const remote = this.manifest(value.remote.commit_id);
        requireMemory(remote.graph_checksum === value.remote.graph_checksum);
        if (value.receipt) validateReceipt(value.receipt, remote, value.remote.revision);
      }
      requireMemory(value.remote.commit_id !== null || (value.remote.revision === 0 && value.remote.graph_checksum === null && value.receipt === null));
      return value;
    } catch {
      this.quarantine(file);
      // Keep immutable commits readable via `show`; never reset a bad ref to
      // empty, which could turn a subsequent pull into destructive success.
      requireMemory(false, "project_memory_integrity_failure");
    }
  }
  save(state: State): void { atomicWrite(join(this.workspace, "state.json"), state); }
  quarantine(file: string): void {
    // Preserve the failed ref in place as a fence and a bounded diagnostic
    // copy. Removing state.json would incorrectly make a corrupt store empty.
    try {
      const raw = boundedRead(file), directory = join(this.base, "quarantine");
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const destination = join(directory, hash(raw) + ".corrupt");
      if (!existsSync(destination)) writeFileSync(destination, raw, { flag: "wx", mode: 0o600 });
    } catch { /* Corruption remains fenced even if the disk is full. */ }
  }
  object(value: unknown): string {
    const id = digest(value);
    const path = join(this.base, "objects", id + ".json");
    if (existsSync(path)) requireMemory(readFileSync(path, "utf8") === canonical(value));
    else atomicWrite(path, value);
    return id;
  }
  graph(id: string): Graph {
    requireMemory(/^[a-f0-9]{64}$/.test(id));
    const file = join(this.base, "objects", id + ".json");
    const raw = boundedRead(file);
    try {
    const value: unknown = JSON.parse(raw);
    validateGraph(value, this.binding.project_id);
    requireMemory(digest(value) === id && canonical(value) === raw);
    return value;
    } catch { this.quarantine(file); requireMemory(false, "project_memory_integrity_failure"); }
  }
  putManifest(manifest: Manifest): void {
    validateManifest(manifest, this.binding.project_id);
    this.graph(manifest.root_object_digest);
    const path = join(this.base, "commits", manifest.commit_id + ".json");
    if (existsSync(path)) requireMemory(readFileSync(path, "utf8") === canonical(manifest));
    else atomicWrite(path, manifest);
  }
  manifest(id: string): Manifest {
    identifier(id, "memc");
    const file = join(this.base, "commits", id + ".json");
    const raw = boundedRead(file);
    try {
    const value: unknown = JSON.parse(raw);
    validateManifest(value, this.binding.project_id);
    requireMemory(canonical(value) === raw);
    this.graph(value.graph_checksum);
    return value;
    } catch { this.quarantine(file); requireMemory(false, "project_memory_integrity_failure"); }
  }
  hasCommit(id: string): boolean { identifier(id, "memc"); return existsSync(join(this.base, "commits", id + ".json")); }
  history(head = this.state().head, until: string | null = null): Manifest[] {
    const result: Manifest[] = [];
    const seen = new Set<string>();
    while (head && head !== until) {
      requireMemory(!seen.has(head) && seen.size < 10000);
      seen.add(head);
      const manifest = this.manifest(head);
      result.push(manifest);
      head = manifest.parent_commit_ids[0] ?? null;
    }
    requireMemory(head === until, "project_memory_head_conflict");
    return result;
  }
  commit(graph: Graph, sourceSha: string, message: string, links: { git?: string[]; prs?: number[]; memory?: string[] } = {}, base?: State): Manifest | null {
    validateGraph(graph, this.binding.project_id);
    const state = base ?? this.state();
    const commitId = "memc_" + randomUUID().replaceAll("-", "");
    const previous = state.head ? this.graph(this.manifest(state.head).graph_checksum) : null;
    graph = withLineage(graph, previous, commitId);
    if (previous && digest(graphContent(previous)) === digest(graphContent(graph))) return null;
    validateGraph(graph, this.binding.project_id);
    const graphDigest = this.object(graph);
    requireMemory(message.length > 0 && message.length <= 2048, "project_memory_message_required");
    const manifest: Manifest = {
      schema_version: 1, commit_id: commitId, graph_id: this.binding.graph_id,
      project_id: this.binding.project_id, parent_commit_ids: state.head ? [state.head] : [], base_revision: state.remote.revision,
      root_object_digest: graphDigest, graph_checksum: graphDigest, builder_version: "git-structure.v1", source_sha: sourceSha,
      source_tree_sha: graph.source_tree_sha, message, change_summary: `${graph.nodes.length} nodes, ${graph.edges.length} edges`,
      linked_git_commits: links.git ?? [], linked_pull_requests: links.prs ?? [], author_principal_id: this.binding.author_principal_id,
      device_id: null, created_at: new Date().toISOString(), policy_digest: digest(graph.policy),
      provenance_refs: [{ source_tree_sha: graph.source_tree_sha }, ...(links.memory ?? []).map((id) => ({ replayed_memory_commit_id: id }))],
    };
    this.putManifest(manifest);
    this.save({ ...state, head: manifest.commit_id, index: null, receipt: null });
    return manifest;
  }
}
