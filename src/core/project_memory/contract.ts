import { createHash } from "node:crypto";

export const MAX_BYTES = 4 * 1024 * 1024;
export const PROJECT_MEMORY_PROTOCOL_VERSION = 1;
export const MAX_NODES = 10000;
export const MAX_EDGES = 20000;
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Entity {
  [key: string]: Json;
  id: string; kind: string; schema_version: number; provenance: Json[];
  tombstone: boolean; visibility: string; sensitivity: string;
}
export interface Graph {
  schema_version: 1; project_id: string; nodes: Entity[]; edges: Entity[];
  partial: boolean; truncation_reasons: string[]; policy: { [key: string]: Json }; source_tree_sha: string;
}
export interface Manifest {
  schema_version: 1; commit_id: string; graph_id: string; project_id: string;
  parent_commit_ids: string[]; base_revision: number; root_object_digest: string; graph_checksum: string;
  builder_version: string; source_sha: string; source_tree_sha: string; message: string; change_summary: string;
  linked_git_commits: string[]; linked_pull_requests: number[]; author_principal_id: string;
  device_id: string | null; created_at: string; policy_digest: string; provenance_refs: Json[];
}
export interface Remote {
  project_id: string; graph_id: string; commit_id: string | null; revision: number;
  graph_checksum: string | null; source_sha?: string | null;
}
export interface Binding {
  project_id: string; graph_id: string; author_principal_id: string; root: string;
  repository_full_name: string; repository_numeric_id: number; binding_digest: string;
  policy?: { auto_commit: boolean; auto_push: boolean; local_builder: boolean };
}
export interface Receipt extends Remote {
  schema_version: 1; type: "aether.project_memory.receipt.v1"; commit_id: string;
  manifest_digest: string; state: "pushed"; signature: string;
}
export class ProjectMemoryError extends Error {
  constructor(readonly code: string) { super(code); }
}
export function requireMemory(condition: unknown, code = "project_memory_integrity_failure"): asserts condition {
  if (!condition) throw new ProjectMemoryError(code);
}
export function canonical(value: unknown): string {
  function render(item: unknown, depth = 0): string {
    requireMemory(depth <= 32);
    if (item === null || typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "number") {
      requireMemory(Number.isSafeInteger(item));
      return JSON.stringify(item);
    }
    if (typeof item === "string") {
      requireMemory(![...item].some((c) => c.length === 1 && c.charCodeAt(0) >= 0xd800 && c.charCodeAt(0) <= 0xdfff));
      return JSON.stringify(item);
    }
    if (Array.isArray(item)) return "[" + item.map((child) => render(child, depth + 1)).join(",") + "]";
    requireMemory(typeof item === "object" && item !== null && Object.getPrototypeOf(item) === Object.prototype);
    const record = item as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map((key) => {
      requireMemory(/^[A-Za-z_][A-Za-z0-9_]*$/.test(key));
      return JSON.stringify(key) + ":" + render(record[key], depth + 1);
    }).join(",") + "}";
  }
  const result = render(value);
  requireMemory(Buffer.byteLength(result) <= MAX_BYTES, "project_memory_limit_exceeded");
  return result;
}
export function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
export function digest(value: unknown): string { return hash(canonical(value)); }
export function identifier(value: unknown, prefix: string): asserts value is string {
  requireMemory(typeof value === "string" && new RegExp(`^${prefix}_[a-zA-Z0-9_-]{8,80}$`).test(value));
}
export function graphId(project: string): string {
  identifier(project, "prj");
  return "pgraph_" + hash("apr-project-memory.v1:" + project).slice(0, 32);
}
export function validateGraph(value: unknown, project: string): asserts value is Graph {
  requireMemory(typeof value === "object" && value !== null);
  const g = value as Graph;
  requireMemory(Object.keys(g).sort().join() === "edges,nodes,partial,policy,project_id,schema_version,source_tree_sha,truncation_reasons");
  requireMemory(g.schema_version === 1 && g.project_id === project && typeof g.partial === "boolean");
  requireMemory(Array.isArray(g.nodes) && g.nodes.length <= MAX_NODES && Array.isArray(g.edges) && g.edges.length <= MAX_EDGES);
  requireMemory(Array.isArray(g.truncation_reasons) && g.policy?.["content_excerpts"] === false && /^[a-f0-9]{40}([a-f0-9]{24})?$/.test(g.source_tree_sha));
  const ids = new Set<string>();
  for (const [family, items] of [["nodes", g.nodes], ["edges", g.edges]] as const) {
    let previous = "";
    for (const e of items) {
      requireMemory(typeof e.id === "string" && /^[A-Za-z0-9_:-]{1,160}$/.test(e.id) && e.id > previous);
      requireMemory(e.schema_version === 1 && typeof e.kind === "string" && Array.isArray(e.provenance) && e.provenance.length > 0 && e.provenance.length <= 20);
      requireMemory(typeof e.tombstone === "boolean" && ["project", "private"].includes(e.visibility) && ["internal", "public", "restricted"].includes(e.sensitivity));
      if (family === "edges") requireMemory(ids.has(e["source"] as string) && ids.has(e["target"] as string));
      else ids.add(e.id);
      previous = e.id;
    }
  }
  canonical(g);
}
export function validateManifest(value: unknown, project: string): asserts value is Manifest {
  requireMemory(typeof value === "object" && value !== null);
  const m = value as Manifest;
  requireMemory(Object.keys(m).sort().join() === ["schema_version", "commit_id", "graph_id", "project_id", "parent_commit_ids", "base_revision", "root_object_digest", "graph_checksum", "builder_version", "source_sha", "source_tree_sha", "message", "change_summary", "linked_git_commits", "linked_pull_requests", "author_principal_id", "device_id", "created_at", "policy_digest", "provenance_refs"].sort().join());
  identifier(m.commit_id, "memc");
  requireMemory(m.schema_version === 1 && m.project_id === project && m.graph_id === graphId(project));
  requireMemory(Array.isArray(m.parent_commit_ids) && m.parent_commit_ids.length <= 2 && new Set(m.parent_commit_ids).size === m.parent_commit_ids.length);
  for (const p of m.parent_commit_ids) { identifier(p, "memc"); requireMemory(p !== m.commit_id); }
  requireMemory(Number.isSafeInteger(m.base_revision) && m.base_revision >= 0);
  for (const d of [m.graph_checksum, m.root_object_digest, m.policy_digest]) requireMemory(typeof d === "string" && /^[a-f0-9]{64}$/.test(d));
  requireMemory(m.root_object_digest === m.graph_checksum);
  for (const s of [m.source_sha, m.source_tree_sha]) requireMemory(typeof s === "string" && /^[a-f0-9]{40}([a-f0-9]{24})?$/.test(s));
  for (const text of [m.message, m.change_summary, m.builder_version, m.author_principal_id, m.created_at]) requireMemory(typeof text === "string" && text.length > 0 && text.length <= 2048);
  for (const a of [m.linked_git_commits, m.linked_pull_requests, m.provenance_refs]) requireMemory(Array.isArray(a) && a.length <= 100);
  requireMemory(m.device_id === null || typeof m.device_id === "string");
  for (const sha of m.linked_git_commits) requireMemory(typeof sha === "string" && /^[a-f0-9]{40}([a-f0-9]{24})?$/.test(sha));
  for (const pr of m.linked_pull_requests) requireMemory(Number.isSafeInteger(pr) && pr > 0);
  canonical(m);
}
export function validateReceipt(value: unknown, manifest: Manifest, revision?: number): asserts value is Receipt {
  const r = value as Receipt;
  requireMemory(r?.type === "aether.project_memory.receipt.v1" && r.schema_version === 1 && r.state === "pushed");
  requireMemory(r.project_id === manifest.project_id && r.graph_id === manifest.graph_id && r.commit_id === manifest.commit_id && r.graph_checksum === manifest.graph_checksum && r.manifest_digest === digest(manifest));
  requireMemory(Number.isSafeInteger(r.revision) && r.revision > 0 && (revision === undefined || r.revision === revision));
  requireMemory(typeof r.signature === "string" && /^[a-f0-9]{64}$/.test(r.signature));
}
