import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalJson, memoryDigest, mergeGraphs, parseGraph, ProjectMemoryWorkingCopy, verifyReceipt,
  type ProjectGraph, type WorkingCopy } from "../src/core/project_memory.js";
import { normalizeMemoryArguments } from "../src/commands/project_memory.js";
import { fileURLToPath } from "node:url";

const project = "prj_0123456789abcdef";
test("Python-generated graph and signed receipt verify without recanonicalization drift", () => {
  const fixture = JSON.parse(readFileSync(fileURLToPath(new URL("../../test/fixtures/project-memory.json", import.meta.url)), "utf8"));
  for (const vector of fixture.vectors) {
    assert.equal(canonicalJson(vector.value), vector.canonical);
    assert.equal(memoryDigest(vector.value), vector.digest);
  }
  assert.equal(memoryDigest(parseGraph(fixture.pack.graph, project)), fixture.pack.checksum);
  assert.equal(verifyReceipt(fixture.pack.attestation, fixture.keys)["graph_checksum"], fixture.pack.checksum);
});
function graph(): ProjectGraph {
  return { schema_version: "ProjectMemoryGraphV1", project_id: project, graph_id: "pgraph_" + "a".repeat(32),
    source_sha: "a".repeat(40), source_tree_sha: "b".repeat(40), policy_digest: "c".repeat(64),
    nodes: [{ id: "file_a", kind: "file", label: "src/main.ts", summary: "", schema_version: 1, locator: null,
      first_seen_commit: null, last_seen_commit: null, confidence_milli: null, tombstone: false, visibility: "project", sensitivity: "internal",
      provenance: { producer: "git", source: "repository_verified",
      evidence_refs: ["d".repeat(64)], policy_digest: "c".repeat(64) } }], edges: [], partial: false, truncation_reasons: [] };
}

test("canonical JSON has Python-compatible number-key order and refuses floats", () => {
  assert.equal(canonicalJson({ z: [1, "é"], a: true }), '{"a":true,"z":[1,"é"]}');
  assert.equal(canonicalJson({ "2": "second", "10": "tenth" }), '{"10":"tenth","2":"second"}');
  for (const value of [1.1, NaN, 9007199254740992, undefined, "\ud800"]) assert.throws(() => canonicalJson(value));
});

test("memory group aliases never reinterpret code -m", () => {
  assert.deepEqual(normalizeMemoryArguments(["-m", "commit", "-m", "verified changes"]), ["memory", "commit", "--message", "verified changes"]);
  assert.deepEqual(normalizeMemoryArguments(["code", "-m", "model"]), ["code", "-m", "model"]);
  assert.deepEqual(normalizeMemoryArguments(["m", "--push"]), ["memory", "push"]);
  assert.throws(() => normalizeMemoryArguments(["memory", "--push", "--pull"]));
});

test("untrusted project identity, dangling edges, and secret content fail closed", () => {
  const value = graph();
  assert.equal(parseGraph(value, project), value);
  assert.throws(() => parseGraph(value, "prj_foreign"));
  assert.throws(() => parseGraph({ ...value, unexpected: true }, project));
  assert.throws(() => parseGraph({ ...value, edges: [{ id: "edge_1", kind: "contains", source: "foreign", target: "file_a", provenance: value.nodes[0]!["provenance"] }] }, project));
  value.nodes[0]!["summary"] = "sk-proj-" + "SECRETCANARY".repeat(5);
  assert.throws(() => parseGraph(value, project));
});

test("only disjoint entity edits auto-merge; delete/update remains a conflict", () => {
  const base = graph(), local = structuredClone(base), remote = structuredClone(base);
  local.nodes.push({ ...local.nodes[0]!, id: "file_b" });
  remote.nodes.push({ ...remote.nodes[0]!, id: "file_c" });
  assert.equal(mergeGraphs(base, local, remote).graph?.nodes.length, 3);
  local.nodes = [];
  remote.nodes[0]!["label"] = "changed";
  const conflict = mergeGraphs(base, local, remote);
  assert.equal(conflict.graph, null);
  assert.equal(conflict.conflicts[0]!.id, "file_a");
});

test("receipt signatures bind every field and reject key substitution", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const payload = { schema_version: "ProjectMemoryReceiptV1", project_id: project, new_revision: 1 };
  const signature = sign(null, Buffer.from(canonicalJson({ key_id: "memory", payload })), privateKey).toString("base64");
  const key = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("base64");
  assert.deepEqual(verifyReceipt({ key_id: "memory", payload, signature }, { memory: key }), payload);
  assert.throws(() => verifyReceipt({ key_id: "memory", payload: { ...payload, new_revision: 2 }, signature }, { memory: key }));
  assert.throws(() => verifyReceipt({ key_id: "foreign", payload, signature }, { memory: key }));
});

test("local atomic working copy detects corruption without overwriting unpushed work", () => {
  const root = mkdtempSync(join(tmpdir(), "aether-project-memory-"));
  try {
    const copy = new ProjectMemoryWorkingCopy(project, root, join(root, "private-data"));
    const value = graph();
    const head = { schema_version: "ProjectMemoryRefV1" as const, project_id: project, graph_id: value.graph_id,
      commit_id: "memc_" + "e".repeat(40), revision: 1, checksum: memoryDigest(value), manifest_checksum: "f".repeat(64),
      source_sha: value.source_sha, cas_token: "0".repeat(64) };
    const state: WorkingCopy = { schema_version: "ProjectMemoryWorkingCopyV1", project_id: project, root,
      remote_identity: "org/repo", base: head, base_graph: value, graph: value, candidate: null,
      conflicts: [], evidence_receipts: [], journal: [{ operation: "init" }] };
    copy.write(state);
    assert.deepEqual(copy.read(), state);
    assert.throws(() => copy.write(state), /stale_state/);
    const file = join(copy.directory, "index.json");
    const raw = readFileSync(file, "utf8").replace("src/main.ts", "poison.ts");
    writeFileSync(file, raw);
    assert.throws(() => copy.read(), /integrity_failure/);
    assert.equal(readFileSync(file, "utf8"), raw);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
