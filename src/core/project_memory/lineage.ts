import { digest, type Entity, type Graph } from "./contract.js";

const STRUCTURAL = new Set(["repository", "directory", "file", "symlink", "submodule", "contains"]);
export function entityContent(entity: Entity): Record<string, unknown> {
  const { first_seen_commit: _first, last_seen_commit: _last, ...content } = entity;
  return content;
}
/** Builder omissions are deletions only for a complete structural scan. */
export function withLineage(graph: Graph, previous: Graph | null, commit: string): Graph {
  const result = structuredClone(graph);
  for (const family of ["nodes", "edges"] as const) {
    const prior = new Map((previous?.[family] ?? []).map((e) => [e.id, e]));
    const seen = new Set<string>();
    result[family] = result[family].map((e) => {
      seen.add(e.id);
      const old = prior.get(e.id);
      return { ...e, first_seen_commit: old?.["first_seen_commit"] ?? commit,
        last_seen_commit: old && digest(entityContent(old)) === digest(entityContent(e)) ? old["last_seen_commit"] ?? commit : commit };
    });
    for (const old of prior.values()) {
      if (seen.has(old.id)) continue;
      result[family].push(!STRUCTURAL.has(old.kind) || graph.partial || old.tombstone ? old :
        { ...old, tombstone: true, last_seen_commit: commit });
    }
    result[family].sort((a, b) => a.id < b.id ? -1 : 1);
  }
  return result;
}
export function graphContent(graph: Graph): unknown {
  return { ...graph, nodes: graph.nodes.map(entityContent), edges: graph.edges.map(entityContent) };
}
