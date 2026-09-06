# Project Memory

Project Memory is an offline-capable, versioned working copy for a canonical Gateway project. It is separate from the existing `memory inspect`, `forget`, and `prune` memory tiers. Opening a project may initialize memory; device activation never scans a repository.

Initialize a repository using its real Gateway project ID:

```text
aether -m init --project <project-id>
aether -m status --offline
aether -m commit --message "Record the verified project structure" --link-git HEAD
aether -m log
aether -m push
aether -m pull
aether -m diff --against remote
aether -m reconcile --no-open
aether --memory-graph --no-open
```

The first-position `-m` alias selects Project Memory. `aether -m --push`, `--pull`, `--commit`, and `--graph` accept one action. Non-leading `-m` keeps its existing message-flag meaning. JSON output reports actual local/remote heads and explicit state; it never invents a remote revision.

`commit` uses immutable Git tree metadata and requires a message. It can run offline. It excludes known secret paths, dependencies, build outputs, ignored paths, binaries, and oversized files. It follows neither symlinks nor submodules and stores no source excerpts. Bounds yield explicit partial graphs. Semantic knowledge from prior snapshots is retained; structural removals become tombstones.

`push` verifies the current canonical repository binding, uploads content-addressed objects, and requests a compare-and-set on the Gateway head. The Gateway must be able to verify the source Git commit/tree through the bound GitHub grant, so publish a new source Git commit before pushing its memory snapshot. A failed write preserves local commits. Retrying a lost acknowledgment recovers the exact server receipt without duplicating a revision.

`pull` never overwrites a dirty index. Disjoint semantic changes may merge when the Git tree agrees; conflicting entity edits or a different source tree preserve both histories and record the conflict. `reconcile` can open the authenticated comparison of the remote revision and its committed base. Local unpublished facts remain available through local `show`/`diff`; they are not falsely presented as Online content.

`--memory-graph` opens the selected local head only after the server resolves that exact committed revision. An unpublished local commit produces an error instead of silently opening an older graph. `--no-open` and headless execution print the URL. Browser launch uses an argument vector and never puts credentials in the URL.

Working copies live beneath the existing Aether config directory at `projects/<project-id>/memory`. Worktrees share immutable objects and have independent state files. Atomic writes, filesystem locking, digest verification, and bounded quarantine copies protect recovery. An abandoned operation lock requires operator inspection; it is never stolen on an assumed timeout. Keep immutable commits and the failed state file when investigating corruption.

Desktop can provide a short-lived project-scoped memory credential through `AETHER_PROJECT_MEMORY_TOKEN`; it is never persisted or exchanged through account-session refresh. Automatic commit/push policy is obtained from the authenticated Gateway head. Standalone pushes remain explicit. A host-generated footer beside coding and PR results rechecks the exact server receipt before reporting pushed status; unavailable verification is stated plainly.

Cloud and Desktop enablement remains gated pending deployment canaries. Shared data schemas and Python/TypeScript vectors are in `contracts/project-memory/v1`; they are not signed APR execution-authority envelopes or Protocol-C proof records.
