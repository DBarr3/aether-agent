import { createHash, randomUUID, createPublicKey, verify } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { configDir } from "./config.js";
import type { ApiClient } from "./transport.js";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Entity = { id: string; kind: string; [key: string]: Json };
export interface ProjectGraph {
  schema_version: "ProjectMemoryGraphV1";
  project_id: string; graph_id: string; source_sha: string; source_tree_sha: string;
  policy_digest: string; nodes: Entity[]; edges: Entity[];
  partial: boolean; truncation_reasons: string[];
}
export interface MemoryHead {
  schema_version: "ProjectMemoryRefV1";
  project_id: string; graph_id: string; commit_id: string; revision: number;
  checksum: string; manifest_checksum: string; source_sha: string; cas_token: string;
}
export interface SignedReceipt { payload: Record<string, Json>; key_id: string; signature: string }
export interface MemoryPack {
  schema_version: "ProjectMemoryPackV1"; head: MemoryHead;
  commit: Record<string, Json>; graph: ProjectGraph; checksum: string; attestation: SignedReceipt;
}
export interface CommitCandidate {
  graph: ProjectGraph; expected_head: string; expected_revision: number; expected_checksum: string;
  idempotency_key: string; message: string; evidence_receipts: SignedReceipt[]; context_seal: null;
}
export interface Conflict { family: string; id: string; reason: string }
export interface WorkingCopy {
  schema_version: "ProjectMemoryWorkingCopyV1";
  project_id: string; root: string; remote_identity: string;
  base: MemoryHead; base_graph: ProjectGraph; graph: ProjectGraph;
  candidate: CommitCandidate | null; conflicts: Conflict[];
  evidence_receipts: SignedReceipt[]; journal: Record<string, Json>[];
}

export class ProjectMemoryError extends Error {
  constructor(readonly code: string) { super(code); }
}

export function canonicalJson(value: unknown): string {
  const visit = (item: unknown): string => {
    if (item === null || typeof item === "boolean") return JSON.stringify(item);
    if (typeof item === "string") {
      if (Buffer.from(item, "utf8").toString("utf8") !== item) throw new ProjectMemoryError("project_memory_integrity_failure");
      return JSON.stringify(item);
    }
    if (typeof item === "number" && Number.isSafeInteger(item)) return JSON.stringify(item);
    if (Array.isArray(item)) return "[" + item.map(visit).join(",") + "]";
    if (item !== null && typeof item === "object") {
      const source = item as Record<string, unknown>;
      return "{" + Object.keys(source).sort().map(key => {
        if (!/^[\x00-\x7f]*$/.test(key)) throw new ProjectMemoryError("project_memory_integrity_failure");
        return JSON.stringify(key) + ":" + visit(source[key]);
      }).join(",") + "}";
    }
    throw new ProjectMemoryError("project_memory_integrity_failure");
  };
  return visit(value);
}

export function memoryDigest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProjectMemoryError("project_memory_integrity_failure");
  return value as Record<string, unknown>;
}
function closed(value: unknown, keys: string[]): Record<string, unknown> {
  const row = object(value);
  if (Object.keys(row).some(key => !keys.includes(key)) || keys.some(key => !(key in row))) {
    throw new ProjectMemoryError("project_memory_integrity_failure");
  }
  return row;
}
const SHA = /^[0-9a-f]{40}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const IDENT = /^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,199}$/;
const NODE_KINDS = new Set("repository directory file module symbol service endpoint schema test dependency concept decision invariant convention risk issue task artifact git_commit branch pull_request release apr_run context_cycle proof".split(" "));
const EDGE_KINDS = new Set("contains imports calls implements tests depends_on documents decided_by supersedes changed_by evidenced_by promotes_from related_to".split(" "));
const SECRET = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})\b|\b(?:password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*["']?[^\s"']{4,}/i;

export function parseGraph(value: unknown, project: string): ProjectGraph {
  const row = closed(value, ["schema_version", "project_id", "graph_id", "source_sha", "source_tree_sha", "policy_digest", "nodes", "edges", "partial", "truncation_reasons"]);
  if (row["schema_version"] !== "ProjectMemoryGraphV1" || row["project_id"] !== project ||
      !/^pgraph_[0-9a-f]{32}$/.test(String(row["graph_id"])) || !SHA.test(String(row["source_sha"])) ||
      !SHA.test(String(row["source_tree_sha"])) || !DIGEST.test(String(row["policy_digest"])) ||
      typeof row["partial"] !== "boolean" || !Array.isArray(row["truncation_reasons"]) ||
      row["truncation_reasons"].length > 16 || row["truncation_reasons"].some(x => typeof x !== "string")) {
    throw new ProjectMemoryError("project_memory_integrity_failure");
  }
  const ids = new Set<string>();
  for (const family of ["nodes", "edges"]) {
    const entries = row[family];
    if (!Array.isArray(entries) || entries.length > (family === "nodes" ? 10000 : 20000)) throw new ProjectMemoryError("project_memory_pack_limit");
    let previous = "";
    for (const entry of entries) {
      const allowed = family === "nodes"
        ? ["id", "kind", "label", "summary", "schema_version", "provenance", "locator", "first_seen_commit", "last_seen_commit", "confidence_milli", "tombstone", "visibility", "sensitivity"]
        : ["id", "kind", "source", "target", "schema_version", "provenance", "tombstone", "visibility", "sensitivity"];
      const e = closed(entry, allowed);
      const id = e["id"];
      if (typeof id !== "string" || typeof e["kind"] !== "string" || !IDENT.test(id) || id <= previous ||
          !(family === "nodes" ? NODE_KINDS : EDGE_KINDS).has(String(e["kind"])) ||
          e["schema_version"] !== 1 || typeof e["tombstone"] !== "boolean" || e["visibility"] !== "project" ||
          !["internal", "restricted"].includes(String(e["sensitivity"]))) throw new ProjectMemoryError("project_memory_integrity_failure");
      previous = id;
      const provenance = closed(e["provenance"], ["producer", "source", "evidence_refs", "policy_digest"]);
      if (typeof provenance["producer"] !== "string" || !IDENT.test(provenance["producer"]) || !["repository_verified", "ci_verified", "human_decision", "verified_promotion"].includes(String(provenance["source"])) ||
          provenance["policy_digest"] !== row["policy_digest"] || !Array.isArray(provenance["evidence_refs"]) ||
          !provenance["evidence_refs"].length || provenance["evidence_refs"].length > 32 || provenance["evidence_refs"].some(x => typeof x !== "string" || !DIGEST.test(x))) {
        throw new ProjectMemoryError("project_memory_evidence_required");
      }
      if (family === "nodes") {
        if (typeof e["label"] !== "string" || !e["label"].length || e["label"].length > 500 ||
            typeof e["summary"] !== "string" || e["summary"].length > 2000 ||
            ["first_seen_commit", "last_seen_commit"].some(k => e[k] !== null && (typeof e[k] !== "string" || !IDENT.test(e[k]))) ||
            (e["confidence_milli"] !== null && (typeof e["confidence_milli"] !== "number" || !Number.isInteger(e["confidence_milli"]) || e["confidence_milli"] < 0 || e["confidence_milli"] > 1000))) {
          throw new ProjectMemoryError("project_memory_integrity_failure");
        }
        if (e["locator"] !== null) {
          const locator = closed(e["locator"], ["path", "tree_sha"]);
          const path = locator["path"];
          if (typeof path !== "string" || !path.length || path.length > 1024 || /^(?:\/|\\)|\.\.|[\\:\x00]/.test(path) || !SHA.test(String(locator["tree_sha"]))) throw new ProjectMemoryError("project_memory_integrity_failure");
        }
        ids.add(id);
      }
      else if (ids.has(id) || typeof e["source"] !== "string" || typeof e["target"] !== "string" || !ids.has(e["source"]) || !ids.has(e["target"])) throw new ProjectMemoryError("project_memory_integrity_failure");
    }
  }
  const raw = canonicalJson(value);
  if (Buffer.byteLength(raw) > 32_000_000) throw new ProjectMemoryError("project_memory_pack_limit");
  if (SECRET.test(raw)) throw new ProjectMemoryError("project_memory_policy_blocked");
  return value as ProjectGraph;
}

export function verifyReceipt(receipt: SignedReceipt, keys: Record<string, string>): Record<string, Json> {
  closed(receipt, ["payload", "key_id", "signature"]);
  const raw = keys[receipt.key_id];
  if (!raw) throw new ProjectMemoryError("project_memory_signature_invalid");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(raw, "base64")]), format: "der", type: "spki" });
  if (!verify(null, Buffer.from(canonicalJson({ key_id: receipt.key_id, payload: receipt.payload })), key, Buffer.from(receipt.signature, "base64"))) {
    throw new ProjectMemoryError("project_memory_signature_invalid");
  }
  return receipt.payload;
}

export function graphDiff(base: ProjectGraph, head: ProjectGraph): Record<string, Json> {
  const result: Record<string, Json> = {};
  for (const family of ["nodes", "edges"] as const) {
    const old = new Map(base[family].map(x => [x.id, x]));
    const next = new Map(head[family].map(x => [x.id, x]));
    result[family] = {
      added: head[family].filter(x => !old.has(x.id)),
      deleted: [...old.keys()].filter(id => !next.has(id)).sort(),
      updated: head[family].filter(x => old.has(x.id) && memoryDigest(old.get(x.id)) !== memoryDigest(x)),
    };
  }
  return result;
}

export function mergeGraphs(base: ProjectGraph, local: ProjectGraph, remote: ProjectGraph): { graph: ProjectGraph | null; conflicts: Conflict[] } {
  const result = structuredClone(remote);
  const conflicts: Conflict[] = [];
  for (const field of ["project_id", "graph_id", "policy_digest", "source_sha", "source_tree_sha"] as const) {
    if (local[field] !== remote[field] && local[field] !== base[field] && remote[field] !== base[field]) {
      conflicts.push({ family: "binding", id: field, reason: "concurrent_change" });
    } else if (remote[field] === base[field]) result[field] = local[field];
  }
  for (const family of ["nodes", "edges"] as const) {
    const maps = [base, local, remote].map(g => new Map(g[family].map(x => [x.id, x])));
    const [b, l, r] = maps as [Map<string, Entity>, Map<string, Entity>, Map<string, Entity>];
    const merged = new Map(r);
    for (const id of [...new Set([...b.keys(), ...l.keys(), ...r.keys()])].sort()) {
      const lc = memoryDigest(l.get(id) ?? null) !== memoryDigest(b.get(id) ?? null);
      const rc = memoryDigest(r.get(id) ?? null) !== memoryDigest(b.get(id) ?? null);
      if (lc && rc) conflicts.push({ family, id, reason: "concurrent_change" });
      else if (lc) { const value = l.get(id); if (value) merged.set(id, value); else merged.delete(id); }
    }
    result[family] = [...merged.values()].sort((a, b) => a.id < b.id ? -1 : 1);
  }
  if (conflicts.length) return { graph: null, conflicts };
  try { return { graph: parseGraph(result, result.project_id), conflicts }; }
  catch { return { graph: null, conflicts: [{ family: "graph", id: "integrity", reason: "invalid_merged_graph" }] }; }
}

export function repositoryIdentity(root: string): { root: string; remote: string; sha: string; tree: string } {
  const real = realpathSync(root);
  const git = (...args: string[]) => execFileSync("git", ["-C", real, ...args], { encoding: "utf8", timeout: 15000, maxBuffer: 1_000_000, windowsHide: true }).trim();
  const remote = git("remote", "get-url", "origin").replace(/\.git$/, "");
  const matched = /^(?:https:\/\/github\.com\/|git@github\.com:)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)$/.exec(remote);
  if (!matched) throw new ProjectMemoryError("project_binding_required");
  const sha = git("rev-parse", "HEAD"), tree = git("rev-parse", "HEAD^{tree}");
  if (!SHA.test(sha) || !SHA.test(tree)) throw new ProjectMemoryError("project_binding_required");
  return { root: real, remote: matched[1]!.toLowerCase(), sha, tree };
}

export class ProjectMemoryWorkingCopy {
  readonly directory: string;
  constructor(readonly project: string, readonly root: string, dataRoot = join(configDir(), "projects")) {
    if (!/^prj_[0-9a-f]{16}$/.test(project)) throw new ProjectMemoryError("project_binding_required");
    this.directory = join(dataRoot, project, "memory", memoryDigest(realpathSync(root)).slice(0, 24));
  }
  read(): WorkingCopy | null {
    const path = join(this.directory, "index.json");
    if (!existsSync(path)) return null;
    try {
      const envelope = JSON.parse(readFileSync(path, "utf8")) as { payload: WorkingCopy; checksum: string };
      if (memoryDigest(envelope.payload) !== envelope.checksum || envelope.payload.project_id !== this.project || envelope.payload.root !== realpathSync(this.root)) throw new Error("mismatch");
      parseGraph(envelope.payload.graph, this.project);
      parseGraph(envelope.payload.base_graph, this.project);
      if (memoryDigest(envelope.payload.base_graph) !== envelope.payload.base.checksum || envelope.payload.graph.graph_id !== envelope.payload.base.graph_id) throw new Error("mismatch");
      return envelope.payload;
    } catch { throw new ProjectMemoryError("project_memory_integrity_failure"); }
  }
  write(state: WorkingCopy): void {
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const lock = join(this.directory, "write.lock");
    let fd: number;
    try { fd = openSync(lock, "wx", 0o600); }
    catch { throw new ProjectMemoryError("project_memory_working_copy_busy"); }
    const temp = join(this.directory, `index.${randomUUID()}.tmp`);
    try {
      const existing = this.read();
      if (existing && state.journal.length !== existing.journal.length + 1) throw new ProjectMemoryError("project_memory_stale_state");
      const content = canonicalJson({ payload: state, checksum: memoryDigest(state) });
      const output = openSync(temp, "wx", 0o600);
      try { writeFileSync(output, content); fsyncSync(output); } finally { closeSync(output); }
      renameSync(temp, join(this.directory, "index.json"));
    } finally { closeSync(fd); unlinkSync(lock); if (existsSync(temp)) unlinkSync(temp); }
  }
}

export class ProjectMemoryClient {
  constructor(readonly api: ApiClient, readonly copy: ProjectMemoryWorkingCopy) {}
  private path(suffix: string): string { return `/gateway/projects/${encodeURIComponent(this.copy.project)}/memory/${suffix}`; }
  private async keys(): Promise<Record<string, string>> {
    const value = await this.api.getJson<{ keys: Record<string, string> }>(this.path("keys"));
    return value.keys;
  }
  private async pack(commit?: string): Promise<MemoryPack> {
    const value = await this.api.getJson<MemoryPack>(this.path(`packs${commit ? `?commit_id=${encodeURIComponent(commit)}` : ""}`));
    parseGraph(value.graph, this.copy.project);
    const signed = verifyReceipt(value.attestation, await this.keys());
    if (value.checksum !== memoryDigest(value.graph) || value.commit["graph_checksum"] !== value.checksum ||
        signed["graph_checksum"] !== value.checksum || signed["commit_digest"] !== memoryDigest(value.commit) ||
        signed["project_id"] !== this.copy.project || memoryDigest(signed["head"]) !== memoryDigest(value.head)) {
      throw new ProjectMemoryError("project_memory_integrity_failure");
    }
    if (typeof signed["repository_full_name"] !== "string" || signed["repository_full_name"].toLowerCase() !== repositoryIdentity(this.copy.root).remote) throw new ProjectMemoryError("project_binding_required");
    return value;
  }
  async status(offline = false): Promise<Record<string, unknown>> {
    const state = this.copy.read();
    const remote = offline ? null : await this.api.getJson<{ head: MemoryHead | null }>(this.path("head"));
    let label = "UNINITIALIZED";
    if (state) {
      const dirty = memoryDigest(state.graph) !== state.base.checksum;
      const behind = remote?.head && remote.head.commit_id !== state.base.commit_id;
      label = state.conflicts.length ? "CONFLICTED" : behind && dirty ? "DIVERGED" : behind ? "BEHIND" : state.candidate ? "AHEAD" : dirty ? "DIRTY" : "CLEAN";
    }
    return { schema_version: "ProjectMemoryStatusV1", project_id: this.copy.project, graph_id: state?.base.graph_id ?? remote?.head?.graph_id ?? null,
      state: label, local_head: state?.candidate?.idempotency_key ?? state?.base.commit_id ?? null,
      remote_head: remote?.head ?? state?.base ?? null, revision: state?.base.revision ?? null,
      checksum: state ? memoryDigest(state.graph) : null, source_sha: state?.graph.source_sha ?? null,
      source_matches_checkout: state ? state.graph.source_sha === repositoryIdentity(this.copy.root).sha : null,
      offline, conflicts: state?.conflicts ?? [] };
  }
  async init(): Promise<Record<string, unknown>> {
    if (this.copy.read()) return this.status();
    const identity = repositoryIdentity(this.copy.root);
    const remote = await this.api.getJson<{head:MemoryHead|null;graph_id:string;genesis_policy:import("./project_memory_genesis.js").GenesisPolicy|null;source:{repository_id:string;repository_full_name:string}}>(this.path("head"));
    if (remote.source.repository_full_name?.toLowerCase() !== identity.remote) throw new ProjectMemoryError("project_binding_required");
    let genesis: {status:string;run_id?:string} = {status:"existing"};
    if (!remote.head) {
      const localGraph = remote.genesis_policy ? (await import("./project_memory_genesis.js")).scanProjectTree(this.copy.root,this.copy.project,remote.graph_id,remote.source.repository_id,identity.sha,identity.tree,remote.genesis_policy) : null;
      genesis = await this.api.postJson(this.path("genesis"), {mode:localGraph?"local":"cloud",source_sha:identity.sha,source_tree_sha:identity.tree,
        idempotency_key:"cli-"+memoryDigest({project:this.copy.project,tree:identity.tree}).slice(0,40),local_graph:localGraph});
    }
    if (genesis.status === "in_progress") {
      if (!genesis.run_id || !/^gen_[0-9a-f]{40}$/.test(genesis.run_id)) throw new ProjectMemoryError("project_memory_integrity_failure");
      let ready = false;
      for (let attempt = 0; attempt < 30; attempt++) {
        const run = await this.api.getJson<{state:string}>(this.path(`genesis/${genesis.run_id}`));
        if (run.state === "READY") { ready = true; break; }
        if (["FAILED", "BLOCKED", "CANCELLED"].includes(run.state)) throw new ProjectMemoryError("project_memory_genesis_blocked");
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
      if (!ready) throw new ProjectMemoryError("project_memory_genesis_in_progress");
    }
    const pack = await this.pack();
    this.copy.write({ schema_version: "ProjectMemoryWorkingCopyV1", project_id: this.copy.project,
      root: identity.root, remote_identity: identity.remote, base: pack.head, base_graph: pack.graph, graph: pack.graph,
      candidate: null, conflicts: [], evidence_receipts: [], journal: [{ operation: "init", commit_id: pack.head.commit_id }] });
    return this.status();
  }
  requireState(): WorkingCopy {
    const state = this.copy.read();
    if (!state) throw new ProjectMemoryError("project_memory_uninitialized");
    if (repositoryIdentity(this.copy.root).remote !== state.remote_identity) throw new ProjectMemoryError("project_binding_required");
    return state;
  }
  stage(graph: unknown, evidence: SignedReceipt[] = []): Record<string, unknown> {
    const state = this.requireState();
    const parsed = parseGraph(graph, this.copy.project);
    if (parsed.graph_id !== state.base.graph_id) throw new ProjectMemoryError("project_binding_required");
    this.copy.write({ ...state, graph: parsed, candidate: null, evidence_receipts: evidence,
      journal: [...state.journal, { operation: "stage", checksum: memoryDigest(parsed) }] });
    return { state: "DIRTY", delta: graphDiff(state.base_graph, parsed) };
  }
  commit(message: string): Record<string, unknown> {
    const state = this.requireState();
    if (state.conflicts.length) throw new ProjectMemoryError("project_memory_head_conflict");
    if (!message.trim() || message.length > 1000 || SECRET.test(message)) throw new ProjectMemoryError("project_memory_policy_blocked");
    const candidate: CommitCandidate = { graph: state.graph, expected_head: state.base.commit_id,
      expected_revision: state.base.revision, expected_checksum: state.base.checksum,
      idempotency_key: "cli-" + randomUUID(), message, evidence_receipts: state.evidence_receipts, context_seal: null };
    this.copy.write({ ...state, candidate, journal: [...state.journal, { operation: "commit", local_commit_digest: memoryDigest(candidate) }] });
    return { state: "AHEAD", local_commit_digest: memoryDigest(candidate), pushed: false };
  }
  async push(): Promise<Record<string, unknown>> {
    const state = this.requireState();
    if (state.conflicts.length || !state.candidate) throw new ProjectMemoryError(state.conflicts.length ? "project_memory_head_conflict" : "project_memory_dirty");
    const receipt = await this.api.postJson<SignedReceipt>(this.path("commits"), state.candidate);
    const claim = verifyReceipt(receipt, await this.keys());
    if (claim["schema_version"] !== "ProjectMemoryReceiptV1" || claim["project_id"] !== this.copy.project || claim["new_checksum"] !== memoryDigest(state.graph) || claim["old_revision"] !== state.base.revision) {
      throw new ProjectMemoryError("project_memory_integrity_failure");
    }
    const head = claim["head"] as unknown as MemoryHead;
    this.copy.write({ ...state, base: head, base_graph: state.graph, candidate: null, evidence_receipts: [],
      journal: [...state.journal, { operation: "push", receipt: receipt as unknown as Json }] });
    return { state: "CLEAN", receipt, head };
  }
  async pull(): Promise<Record<string, unknown>> {
    const state = this.requireState();
    const pack = await this.pack();
    if (pack.head.commit_id === state.base.commit_id) return this.status();
    const dirty = memoryDigest(state.graph) !== state.base.checksum;
    const merged = dirty ? mergeGraphs(state.base_graph, state.graph, pack.graph) : { graph: pack.graph, conflicts: [] };
    if (!merged.graph) {
      this.copy.write({ ...state, conflicts: merged.conflicts, journal: [...state.journal,
        { operation: "conflict", remote_head: pack.head as unknown as Json, remote_graph: pack.graph as unknown as Json }] });
      return { state: "CONFLICTED", conflicts: merged.conflicts };
    }
    this.copy.write({ ...state, base: pack.head, base_graph: pack.graph, graph: merged.graph,
      candidate: null, conflicts: [], evidence_receipts: [], journal: [...state.journal, { operation: "pull", commit_id: pack.head.commit_id }] });
    return this.status();
  }
  reconcile(graph: unknown, evidence: SignedReceipt[]): Record<string, unknown> {
    const state = this.requireState();
    const conflict = [...state.journal].reverse().find(row => row["operation"] === "conflict");
    if (!conflict || !state.conflicts.length) throw new ProjectMemoryError("project_memory_no_conflict");
    const parsed = parseGraph(graph, this.copy.project);
    if (parsed.graph_id !== state.base.graph_id) throw new ProjectMemoryError("project_binding_required");
    this.copy.write({ ...state, base: conflict["remote_head"] as unknown as MemoryHead,
      base_graph: conflict["remote_graph"] as unknown as ProjectGraph, graph: parsed,
      evidence_receipts: evidence, conflicts: [], candidate: null,
      journal: [...state.journal, { operation: "reconcile", checksum: memoryDigest(parsed) }] });
    return { state: "DIRTY", resolved: true, pushed: false };
  }
  async open(): Promise<string> {
    const result = await this.api.getJson<{ open_url: string }>(this.path("open"));
    const url = new URL(result.open_url);
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || [...url.searchParams.keys()].some(key => /token|secret|credential/i.test(key))) {
      throw new ProjectMemoryError("project_memory_unsafe_url");
    }
    return result.open_url;
  }
  async log(offline = false): Promise<unknown> {
    return offline ? this.requireState().journal : this.api.getJson(this.path("commits"));
  }
  async show(commit: string): Promise<unknown> {
    if (!/^memc_[0-9a-f]{40}$/.test(commit)) throw new ProjectMemoryError("project_memory_invalid_commit");
    return this.api.getJson(this.path(`commits/${encodeURIComponent(commit)}`));
  }
}
