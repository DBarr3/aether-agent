# Project Memory

Project Memory is a separate, Gateway-bound store of verified project knowledge.
It does not replace owner-scoped personal memory or the per-run Context Overpool.
Use an exact Gateway project ID and a repository with its canonical GitHub origin:

```sh
aether memory init --project prj_0123456789abcdef
aether memory status --project prj_0123456789abcdef --json
aether memory pull --project prj_0123456789abcdef
aether memory graph --project prj_0123456789abcdef --no-open
```

The ID above is illustrative. It must be replaced with a real project returned
by Gateway. `init` first verifies origin against the canonical binding and pulls
an existing signed graph. Otherwise it scans the exact committed local Git tree
under the current root, with the server's bounded inclusion policy. It reads
committed ignore rules into a private temporary directory and never publishes
uncommitted source, secrets, binaries or symlink targets. Cloud acceptance must
independently reproduce the candidate against the same GitHub tree. A source
that cannot be verified remains blocked.

Local working indexes are stored privately outside the source repository and
separated by root realpath. Atomic replacement and integrity checks preserve
unpushed work on corruption. Multiple worktrees share the canonical cloud graph
but keep separate local indexes.

To propose new knowledge, supply a closed `ProjectMemoryGraphV1` JSON file and
independent evidence receipts:

```sh
aether memory stage graph.json --evidence-file evidence.json --project PROJECT_ID
aether memory diff --project PROJECT_ID
aether memory commit -m "Verified project knowledge" --project PROJECT_ID
aether memory push --project PROJECT_ID
```

Commit is local and never implicitly pushes. Push requires independently signed
evidence covering changed/deleted entity IDs and uses the exact base head,
revision and checksum. A model-generated assertion is not an evidence receipt.
`sync` pulls and then pushes a pending candidate only if the base remains safe.
Disjoint identities may merge; conflicting changes are retained explicitly and
must be reconciled with a graph/evidence file before another local commit.

Additional commands: `log`, `show <commit>`, `reconcile <graph-file>` and
`--offline` inspection. The alias `aether m` (or leading `aether -m`) belongs to
this command group; `aether code -m` keeps its existing model meaning. The
unrelated personal-memory `inspect`, `forget` and `prune` commands remain intact.

The JSON envelope reports actual state, receipts and safe errors. Graph opening
uses Gateway's credential-free URL and the existing safe browser opener. The
bundled APR skill teaches retrieval/evidence workflow without granting new tool
permissions. Hosted context production gates and large-reach benchmarks remain
the cloud/daemon release owner's responsibility.
