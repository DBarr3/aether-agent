import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative } from "node:path";
import { digest, hash, MAX_NODES, requireMemory, type Entity, type Graph } from "./contract.js";

export const BUILDER_VERSION = "git-structure.v1";
const DENIED = /(^|\/)(\.git|\.env(?:\..*)?|\.npmrc|\.pypirc|\.netrc|\.ssh|credentials(?:\..*)?|id_rsa|id_ed25519|node_modules|vendor|dist|build|coverage|__pycache__|\.cache)(\/|$)|\.(pem|key|p12|pfx|exe|dll|so|zip|gz|png|jpg|jpeg|gif|pdf|mp4|mp3|woff2?)$/i;
const NULL_GIT_CONFIG = "/dev/null";
const MAX_IGNORE_FILES = 64;
const MAX_IGNORE_BYTES = 64 * 1024;

interface GitEntry {
  mode: string;
  type: "blob" | "commit";
  objectSha: string;
  size: number;
  path: string;
}

function gitEnvironment(): NodeJS.ProcessEnv {
  // Repository-local configuration remains available, while machine-specific
  // ignore rules and replacement objects cannot change a canonical scan.
  const environment = { ...process.env };
  for (const key of ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_CONFIG_PARAMETERS"]) {
    delete environment[key];
  }
  return { ...environment, GIT_CONFIG_COUNT: "0", GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: NULL_GIT_CONFIG, GIT_NO_REPLACE_OBJECTS: "1" };
}

export function git(root: string, args: string[], input?: string): string {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 8 * 1024 * 1024, timeout: 30000, windowsHide: true,
    env: gitEnvironment(), ...(input === undefined ? {} : { input }), stdio: ["pipe", "pipe", "pipe"] });
}
function gitBytes(root: string, args: string[]): Buffer {
  return execFileSync("git", ["-C", root, ...args], { maxBuffer: 128 * 1024, timeout: 30000, windowsHide: true,
    env: gitEnvironment(), stdio: ["pipe", "pipe", "pipe"] });
}
function parseEntries(raw: string): GitEntry[] {
  return raw.split("\0").filter(Boolean).map((line) => {
    const match = /^(\d{6}) (blob|commit) ([a-f0-9]{40}|[a-f0-9]{64})\s+(\d+|-)\t([\s\S]+)$/.exec(line);
    requireMemory(match, "project_memory_source_unavailable");
    const path = match[5]!;
    const parts = path.split("/");
    requireMemory(
      !path.startsWith("/") && Buffer.byteLength(path) <= 1024 && parts.length <= 64 &&
      parts.every((part) => part.length > 0 && part !== "." && part !== "..") && !/[\x00-\x1f\\:]/.test(path),
      "project_memory_source_unavailable",
    );
    const size = match[4] === "-" ? 0 : Number(match[4]);
    requireMemory(Number.isSafeInteger(size) && size >= 0, "project_memory_source_unavailable");
    return { mode: match[1]!, type: match[2]! as "blob" | "commit", objectSha: match[3]!, size, path };
  });
}
function checkIgnored(root: string, paths: string[]): Set<string> {
  if (!paths.length) return new Set();
  try {
    return new Set(git(root, ["-c", `core.excludesFile=${NULL_GIT_CONFIG}`, "-c", "core.ignoreCase=false",
      "check-ignore", "--no-index", "-z", "--stdin"], paths.join("\0") + "\0").split("\0").filter(Boolean));
  } catch (error) {
    const result = error as { status?: number };
    if (result.status === 1) return new Set();
    throw error;
  }
}
function committedIgnoredPaths(root: string, entries: GitEntry[]): Set<string> {
  // Evaluate ignore rules in an empty private repository populated solely with
  // .gitignore blobs from the selected commit. Dirty files, global excludes,
  // and .git/info/exclude therefore cannot alter the graph.
  const parent = realpathSync(tmpdir());
  const prefix = "aether-memory-ignore-";
  const temporary = mkdtempSync(join(parent, prefix));
  try {
    git(temporary, ["init", "--quiet", "--template="]);
    const ignoreFiles = entries
      .filter((entry) => entry.type === "blob" && entry.mode !== "120000" && entry.path.split("/").at(-1) === ".gitignore" && !DENIED.test(entry.path))
      .sort((left, right) => left.path.split("/").length - right.path.split("/").length || Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
    let admitted = 0;
    for (const entry of ignoreFiles) {
      if (checkIgnored(temporary, [entry.path]).has(entry.path)) continue;
      requireMemory(++admitted <= MAX_IGNORE_FILES && entry.size <= MAX_IGNORE_BYTES, "project_memory_limit_exceeded");
      const destination = join(temporary, ...entry.path.split("/"));
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      const contents = gitBytes(root, ["cat-file", "blob", entry.objectSha]);
      requireMemory(contents.byteLength === entry.size && contents.byteLength <= MAX_IGNORE_BYTES, "project_memory_source_unavailable");
      writeFileSync(destination, contents, { mode: 0o600 });
    }
    return checkIgnored(temporary, entries.map((entry) => entry.path));
  } finally {
    const resolved = realpathSync(temporary);
    const child = relative(parent, resolved);
    if (!isAbsolute(child) && child.startsWith(prefix) && dirname(child) === ".") rmSync(resolved, { recursive: true, force: true });
  }
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
  requireMemory(/^[a-f0-9]{40}([a-f0-9]{24})?$/.test(sourceSha) && /^[a-f0-9]{40}([a-f0-9]{24})?$/.test(tree), "project_memory_source_unavailable");
  const entries = parseEntries(git(root, ["ls-tree", "-rlz", "--full-tree", sourceSha]));
  const ignored = committedIgnoredPaths(root, entries);
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
  for (const entry of entries) {
    if (DENIED.test(entry.path) || ignored.has(entry.path)) continue;
    if (entry.size > 1024 * 1024) continue;
    const requiredNodes = entry.path.split("/").length;
    if (nodes.length + requiredNodes >= MAX_NODES || bytes > 2 * 1024 * 1024) { reasons.push("structural_graph_cap"); break; }
    const kind = entry.mode === "160000" ? "submodule" : entry.mode === "120000" ? "symlink" : "file";
    add(kind, entry.path, { git_object_sha: entry.objectSha, size: entry.size });
    bytes += Buffer.byteLength(entry.path) + 700;
  }
  const graph: Graph = { schema_version: 1, project_id: project, nodes: nodes.sort((a, b) => a.id < b.id ? -1 : 1),
    edges: edges.sort((a, b) => a.id < b.id ? -1 : 1), partial: reasons.length > 0, truncation_reasons: reasons,
    source_tree_sha: tree, policy: { content_excerpts: false, builder_version: BUILDER_VERSION, secret_paths_denied: true,
      ignored_paths_digest: digest([...ignored].sort()), max_file_bytes: 1048576, max_nodes: MAX_NODES } };
  return { graph, sourceSha };
}
