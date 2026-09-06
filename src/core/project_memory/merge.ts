import { digest, type Entity, type Graph } from "./contract.js";
import { entityContent } from "./lineage.js";

const STRUCTURAL = new Set(["repository", "directory", "file", "symlink", "submodule", "contains"]);
/** Three-way merge of semantic entities. Structural facts come from a pinned rebuild. */
export function mergeGraphs(base: Graph, local: Graph, remote: Graph, structure: Graph): { graph: Graph; conflicts: string[] } {
  const graph = structuredClone(structure), conflicts: string[] = [];
  const fingerprint = (e?: Entity) => e ? digest(entityContent(e)) : null;
  for (const family of ["nodes", "edges"] as const) {
    const map = (g: Graph) => new Map(g[family].filter((e) => !STRUCTURAL.has(e.kind)).map((e) => [e.id, e]));
    const ancestor = map(base), ours = map(local), theirs = map(remote);
    for (const id of new Set([...ancestor.keys(), ...ours.keys(), ...theirs.keys()])) {
      const a = ancestor.get(id), l = ours.get(id), r = theirs.get(id);
      const ad = fingerprint(a), ld = fingerprint(l), rd = fingerprint(r);
      if (ld !== ad && rd !== ad && ld !== rd) { conflicts.push(id); continue; }
      const selected = ld === ad ? r : l;
      if (selected) graph[family].push(structuredClone(selected));
    }
    graph[family].sort((a, b) => a.id < b.id ? -1 : 1);
  }
  return { graph, conflicts: conflicts.sort() };
}
