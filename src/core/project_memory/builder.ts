import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { digest, hash, MAX_NODES, requireMemory, type Entity, type Graph } from "./contract.js";

export const BUILDER_VERSION = "git-structure.v1";
const DENIED = /(^|\/)(\.git|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|\.ssh|credentials(?:\..*)?|id_rsa|id_ed25519|node_modules|vendor|dist|build|coverage|__pycache__|\.cache)(\/|$)|\.(pem|key|p12|pfx|exe|dll|so|zip|gz|png|jpg|jpeg|gif|pdf|mp4|mp3|woff2?)$/i;

export function git(root: string, args: string[], input?: string): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 30000, windowsHide: true,
    ...(input === undefined ? {} : { input }), stdio: ["pipe", "pipe", "pipe"] });
}
export function repositoryRoot(cwd: string): string {
  return realpathSync(git(cwd, ["rev-parse", "--show-toplevel"]).trim());
}
export function repositoryName(root: string): string {
  const remote = git(root, ["remote", "get-url", "origin"]).trim();
  const match = /^(?:https:\/\/github\.com\/|git@github\.com:)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(remote);
  requireMemory(match?.[1], "project_binding_required");
  return match[1].toLowerCase();
}
export function buildGraph(root: string, project: string): { graph: Graph; sourceSha: string } {
  // Inspect immutable Git metadata only. Symlink and submodule entries are
  // references, never followed; no repository source blob is copied to memory.
  const sourceSha = git(root, ["rev-parse", "--verify", "HEAD^{commit}"]).trim();
  const tree = git(root, ["rev-parse", "--verify", `${sourceSha}^{tree}`]).trim();
  const entries = git(root, ["ls-tree", "-rlz", "--full-tree", sourceSha]).split("\0").filter(Boolean);
  const paths = entries.map((line) => line.slice(line.indexOf("\t") + 1));
  let ignored = new Set<string>();
  if (paths.length) {
    try {
      ignored = new Set(git(root, ["check-ignore", "--no-index", "-z", "--stdin"], paths.join("\0") + "\0").split("\0").filter(Boolean));
    } catch (e) {
      const error = e as { status?: number; stdout?: string };
      if (error.status !== 1) throw e;
    }
  }
  const nodes: Entity[] = [], edges: Entity[] = [], reasons: string[] = [];
  const byPath = new Map<string, string>();
  const idFor = (kind: string, locator: string) => "node_" + hash(`${project}:${kind}:${locator}`);
  function add(kind: string, path: string, metadata: Record<string, string | number> = {}): string {
    const id = idFor(kind, path);
    if (byPath.has(path)) return byPath.get(path)!;
    byPath.set(path, id);
    nodes.push({ id, kind, schema_version: 1, provenance: [{ source_tree_sha: tree, path }], tombstone: false,
      visibility: "project", sensitivity: "internal", first_seen_commit: null, last_seen_commit: null,
      locator: path, ...metadata });
    if (path) {
      const parentPath = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
      const parent = add(parentPath ? "directory" : "repository", parentPath);
      edges.push({ id: "edge_" + hash(`${project}:contains:${parent}:${id}`), kind: "contains", schema_version: 1,
        source: parent, target: id, provenance: [{ source_tree_sha: tree }], tombstone: false,
        visibility: "project", sensitivity: "internal", first_seen_commit: null, last_seen_commit: null });
    }
    return id;
  }
  add("repository", "");
  let bytes = 0;
  for (const line of entries) {
    const separator = line.indexOf("\t");
    const meta = line.slice(0, separator), path = line.slice(separator + 1);
    requireMemory(meta && path && !path.startsWith("/") && !path.split("/").includes("..") && !/[\x00-\x1f\\]/.test(path));
    const [mode, , objectSha, size] = meta.trim().split(/\s+/);
    if (DENIED.test(path) || ignored.has(path)) continue;
    if (Number(size) > 1024 * 1024) continue;
    const requiredNodes = path.split("/").length;
    if (nodes.length + requiredNodes >= MAX_NODES || bytes > 2 * 1024 * 1024) { reasons.push("structural_graph_cap"); break; }
    const kind = mode === "160000" ? "submodule" : mode === "120000" ? "symlink" : "file";
    add(kind, path, { git_object_sha: objectSha ?? "", size: Number(size) || 0 });
    bytes += Buffer.byteLength(path) + 700;
  }
  const graph: Graph = { schema_version: 1, project_id: project, nodes: nodes.sort((a, b) => a.id < b.id ? -1 : 1),
    edges: edges.sort((a, b) => a.id < b.id ? -1 : 1), partial: reasons.length > 0, truncation_reasons: reasons,
    source_tree_sha: tree, policy: { content_excerpts: false, builder_version: BUILDER_VERSION, secret_paths_denied: true,
      ignored_paths_digest: digest([...ignored].sort()), max_file_bytes: 1048576, max_nodes: MAX_NODES } };
  return { graph, sourceSha };
}
