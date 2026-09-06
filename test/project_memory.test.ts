import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { buildGraph, git } from "../src/core/project_memory/builder.js";
import { canonical, digest, graphId, type Binding, type Graph, type Manifest, type Receipt, type Remote } from "../src/core/project_memory/contract.js";
import { ProjectStore } from "../src/core/project_memory/store.js";
import { pull, push } from "../src/core/project_memory/sync.js";
import { normalizeMemoryArgs } from "../src/commands/project_memory.js";
import type { ApiClient } from "../src/core/transport.js";
import { validateGraph, validateManifest } from "../src/core/project_memory/contract.js";

const project = "prj_12345678";
test("TypeScript consumes the same canonical contract bytes as Gateway", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../contracts/project-memory/v1/vectors.json", import.meta.url), "utf8"));
  validateGraph(vectors.graph, vectors.graph.project_id);
  validateManifest(vectors.manifest, vectors.graph.project_id);
  assert.equal(digest(vectors.graph), vectors.graph_digest);
  assert.equal(digest(vectors.manifest), vectors.manifest_digest);
  for (const value of vectors.canonical_cases) assert.equal(digest(value.value), value.sha256);
  for (const patch of [{ schema_version: true }, { parent_commit_ids: [[]] }, { linked_pull_requests: [true] }, { base_revision: 0.5 }, { extra: "data" }]) {
    assert.throws(() => validateManifest({ ...vectors.manifest, ...patch }, vectors.graph.project_id));
  }
});
function fixture(): { root: string; store: ProjectStore; binding: Binding } {
  const data = mkdtempSync(join(tmpdir(), "apr-memory-"));
  const root = join(data, "repo"); mkdirSync(root);
  git(root, ["init"]);
  git(root, ["config", "user.name", "Test"]); git(root, ["config", "user.email", "test@example.invalid"]);
  git(root, ["remote", "add", "origin", "https://github.com/test/repo.git"]);
  writeFileSync(join(root, "README.md"), "hello\n");
  git(root, ["add", "."]); git(root, ["commit", "-m", "fixture"]);
  const binding = { project_id: project, graph_id: graphId(project), author_principal_id: "owner", root,
    repository_numeric_id: 17, repository_full_name: "test/repo", binding_digest: "sha256:" + "a".repeat(64) };
  const store = new ProjectStore(binding, data); store.initialize();
  return { root, store, binding };
}
function commit(store: ProjectStore, root: string, message = "Genesis"): Manifest {
  const built = buildGraph(root, project);
  return store.commit(built.graph, built.sourceSha, message)!;
}
class Server {
  head: Remote = { project_id: project, graph_id: graphId(project), commit_id: null, revision: 0, graph_checksum: null };
  objects = new Map<string, Graph>();
  commits = new Map<string, { manifest: Manifest; graph: Graph; receipt: Receipt; revision: number }>();
  writes = 0;
  loseResponse = false;
  api = {
    getJson: async (path: string) => {
      if (path.endsWith("/head")) return { ...this.head, schema_version: 1, author_principal_id: "owner",
        binding: { repository_numeric_id: 17, repository_full_name: "test/repo", binding_digest: "sha256:" + "a".repeat(64) } };
      const id = new URL(path, "https://test.invalid").searchParams.get("commit_id")!;
      const snapshot = this.commits.get(id);
      assert.ok(snapshot, `missing commit ${id}`);
      return { ...snapshot, project_id: project, graph_id: graphId(project), open_url: `https://test.invalid/platform/online/graph?project=${project}&memoryCommit=${id}` };
    },
    postJson: async (path: string, body: Record<string, unknown>) => {
      if (path.endsWith("/packs")) {
        for (const obj of body["objects"] as { digest: string; value: Graph }[]) { assert.equal(digest(obj.value), obj.digest); this.objects.set(obj.digest, obj.value); }
        return {};
      }
      const m = body["commit_manifest"] as Manifest;
      assert.equal(body["expected_head_commit_id"], this.head.commit_id);
      assert.equal(body["expected_revision"], this.head.revision);
      const graph = this.objects.get(m.graph_checksum)!; assert.ok(graph);
      this.head = { ...this.head, commit_id: m.commit_id, revision: this.head.revision + 1, graph_checksum: m.graph_checksum };
      const receipt: Receipt = { ...this.head, commit_id: m.commit_id, schema_version: 1, type: "aether.project_memory.receipt.v1", manifest_digest: digest(m), state: "pushed", signature: "a".repeat(64) };
      this.commits.set(m.commit_id, { manifest: m, graph, receipt, revision: receipt.revision }); this.writes++;
      if (this.loseResponse) { this.loseResponse = false; throw new Error("lost response"); }
      return { receipt };
    },
  } as unknown as ApiClient;
}

test("memory parser normalizes only first-position aliases and one action", () => {
  for (const action of ["commit", "push", "pull", "graph"]) {
    assert.deepEqual(normalizeMemoryArgs(["-m", action]), ["memory", action]);
    assert.deepEqual(normalizeMemoryArgs(["-m", `--${action}`]), ["memory", action]);
  }
  assert.deepEqual(normalizeMemoryArgs(["code", "-m", "x"]), ["code", "-m", "x"]);
  assert.deepEqual(normalizeMemoryArgs(["--memory-graph", "--no-open"]), ["memory", "graph", "--no-open"]);
  assert.throws(() => normalizeMemoryArgs(["-m", "--push", "--pull"]));
});

test("canonical JSON rejects floats and lone surrogates and sorts keys", () => {
  assert.equal(canonical({ z: "café", a: 1 }), '{"a":1,"z":"café"}');
  for (const value of [NaN, Infinity, 1.1, 9007199254740992, "\ud800", { "bad-key": 1 }]) assert.throws(() => canonical(value));
});

test("deterministic Git builder excludes secrets, ignored and binary files without source contents", () => {
  const { root } = fixture();
  writeFileSync(join(root, ".env"), "SENTINEL_CREDENTIAL=unsafe");
  writeFileSync(join(root, ".gitignore"), "ignored.txt\n");
  writeFileSync(join(root, "ignored.txt"), "ignored"); writeFileSync(join(root, "file.png"), Buffer.alloc(20));
  git(root, ["add", "-f", ".env", ".gitignore", "ignored.txt", "file.png"]); git(root, ["commit", "-m", "fixtures"]);
  const first = buildGraph(root, project), second = buildGraph(root, project);
  assert.equal(digest(first.graph), digest(second.graph));
  assert.ok(!canonical(first.graph).includes("SENTINEL_CREDENTIAL"));
  const locators = first.graph.nodes.map((n) => n["locator"]);
  assert.ok(!locators.includes(".env") && !locators.includes("ignored.txt") && !locators.includes("file.png"));
  assert.ok(locators.includes("README.md"));
});

test("local commit and immutable objects work with no network and detect corruption", async () => {
  const { root, store } = fixture();
  const manifest = await store.locked(() => commit(store, root));
  assert.equal(store.state().head, manifest.commit_id); assert.equal(store.state().remote.revision, 0);
  assert.equal(store.history().length, 1);
  assert.equal(store.commit(buildGraph(root, project).graph, manifest.source_sha, "unchanged"), null);
  writeFileSync(join(store.base, "objects", manifest.graph_checksum + ".json"), "{}");
  assert.throws(() => store.manifest(manifest.commit_id), /integrity/);
});

test("worktrees have independent heads and operation locks exclude racing writers", async () => {
  const { root, store, binding } = fixture();
  await store.locked(async () => {
    await assert.rejects(store.locked(() => 1), /locked/);
    commit(store, root);
  });
  const other = new ProjectStore({ ...binding, root: root + "-worktree" });
  assert.notEqual(other.workspace, store.workspace);
  assert.equal(other.state().head, null);
});

test("push then second-device pull preserves exact revision and receipt", async () => {
  const first = fixture(), second = fixture(), server = new Server();
  const originalGit = git(first.root, ["rev-parse", "HEAD"]);
  const m = await first.store.locked(() => commit(first.store, first.root));
  await first.store.locked(() => push(first.store, server.api));
  await second.store.locked(() => pull(second.store, server.api));
  assert.equal(second.store.state().head, m.commit_id);
  assert.equal(second.store.state().receipt?.revision, 1);
  assert.equal(git(first.root, ["rev-parse", "HEAD"]), originalGit);
});

test("two-device divergence preserves both commits and rejects overwrite", async () => {
  const first = fixture(), second = fixture(), server = new Server();
  await first.store.locked(() => commit(first.store, first.root));
  const local = await second.store.locked(() => commit(second.store, second.root));
  await first.store.locked(() => push(first.store, server.api));
  await assert.rejects(second.store.locked(() => push(second.store, server.api)), /head_conflict/);
  await assert.rejects(second.store.locked(() => pull(second.store, server.api)), /head_conflict/);
  assert.equal(second.store.state().head, local.commit_id);
  assert.equal(server.writes, 1);
});

test("lost acknowledgment during a multi-commit push resumes without duplication", async () => {
  const { root, store } = fixture(), server = new Server();
  await store.locked(() => commit(store, root));
  writeFileSync(join(root, "next.txt"), "next"); git(root, ["add", "."]); git(root, ["commit", "-m", "next"]);
  const last = await store.locked(() => commit(store, root, "Next"));
  server.loseResponse = true;
  await assert.rejects(store.locked(() => push(store, server.api)), /lost response/);
  assert.equal(store.state().remote.revision, 0);
  await store.locked(() => push(store, server.api));
  assert.equal(store.state().remote.commit_id, last.commit_id);
  assert.equal(store.state().remote.revision, 2); assert.equal(server.writes, 2);
  await store.locked(() => push(store, server.api)); assert.equal(server.writes, 2);
});

test("dirty index prevents remote overwrite and corrupt state never resets to empty", async () => {
  const first = fixture(), second = fixture(), server = new Server();
  await first.store.locked(() => commit(first.store, first.root)); await first.store.locked(() => push(first.store, server.api));
  await second.store.locked(() => {
    const index = second.store.object(buildGraph(second.root, project).graph);
    second.store.save({ ...second.store.state(), index });
  });
  await assert.rejects(second.store.locked(() => pull(second.store, server.api)), /dirty/);
  assert.equal(second.store.state().head, null);
  const statePath = join(second.store.workspace, "state.json");
  const saved = readFileSync(statePath, "utf8"); writeFileSync(statePath, "{");
  assert.throws(() => second.store.state(), /integrity/);
  writeFileSync(statePath, saved);
});

test("complete scans tombstone removals, retain first-seen history, and unchanged commits are no-ops", async () => {
  const { root, store } = fixture();
  const first = await store.locked(() => commit(store, root));
  assert.equal(await store.locked(() => commit(store, root)), null);
  git(root, ["rm", "README.md"]); git(root, ["commit", "-m", "remove"]);
  const next = await store.locked(() => commit(store, root, "Remove README"));
  const graph = store.graph(next.graph_checksum);
  const removed = graph.nodes.find((n) => n["locator"] === "README.md")!;
  assert.equal(removed.tombstone, true);
  assert.equal(removed["first_seen_commit"], first.commit_id);
  assert.equal(removed["last_seen_commit"], next.commit_id);
  assert.equal(await store.locked(() => commit(store, root)), null);
});

test("pull merges disjoint semantic IDs and retains the original local branch", async () => {
  const a = fixture(), b = fixture(), server = new Server();
  await a.store.locked(() => commit(a.store, a.root));
  await a.store.locked(() => push(a.store, server.api));
  await b.store.locked(() => pull(b.store, server.api));
  const add = (store: ProjectStore, id: string) => {
    const built = buildGraph(store.binding.root, project);
    built.graph.nodes.push({ ...built.graph.nodes[0]!, id, kind: "decision", summary: id });
    built.graph.nodes.sort((x, y) => x.id < y.id ? -1 : 1);
    return store.commit(built.graph, built.sourceSha, "Decision")!;
  };
  await a.store.locked(() => add(a.store, "node_decision_a"));
  const oldLocal = await b.store.locked(() => add(b.store, "node_decision_b"));
  await a.store.locked(() => push(a.store, server.api));
  assert.equal(await b.store.locked(() => pull(b.store, server.api)), "local");
  assert.ok(b.store.hasCommit(oldLocal.commit_id));
  const current = b.store.manifest(b.store.state().head!);
  assert.equal(current.parent_commit_ids[0], server.head.commit_id);
  assert.deepEqual(b.store.graph(current.graph_checksum).nodes.filter((e) => e.kind === "decision").map((e) => e.id), ["node_decision_a", "node_decision_b"]);
  await b.store.locked(() => push(b.store, server.api));
  assert.equal(server.head.revision, 3);
});
