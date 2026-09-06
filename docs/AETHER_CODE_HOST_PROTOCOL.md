# Aether Code private host protocol

`aether.code.host/1` is the private supervision channel between Aether Cloud
and one disposable Aether Code worker serving one admitted attempt. This file
freezes the Phase 0 wire contract. It does not define a public CLI and it does
not implement the worker, launcher, supervisor, credential broker, or host
action executor.

The existing execution stream remains authoritative and byte/schema compatible:

- worker stdout: `aether.exec/2` JSONL;
- worker stdin: `aether.exec.control/2` JSONL;
- worker stderr: bounded, redacted diagnostics only;
- private inherited IPC: `aether.code.host/1` frames from this document.

Host actions, heartbeats, credentials, and supervisor leases never ride on the
execution stream. Execution progress and terminal outcomes never ride on the
private host channel. A future incompatible host change uses
`aether.code.host/2`; an incompatible execution change uses `aether.exec/3`.

## Transport and framing

Each host-channel message is one UTF-8 JSON object. The transport supplies
message boundaries or newline delimiters without changing the JSON bytes.
Frames are at most 65,536 bytes. The channel has independent monotonically
increasing `sequence` values in each direction, beginning at zero:

- worker: `hello` is sequence 0; `ready` is the next worker frame;
- Cloud: `start` is sequence 0; later lease/action responses follow it.

A missing, future, conflicting duplicate, malformed, oversized, or
wrong-direction frame is fatal to the active handshake/attempt. A byte-identical
duplicate may be delivered to an idempotency ledger, but it must never repeat an
effect. `action_id`, `idempotency_key`, attempt identity, and lease epoch bind
host-action effects independently of delivery sequence.

All object keys are snake_case. Unknown top-level or nested fields fail closed.
The only version-1 feature names are `host_actions_v1` and
`supervisor_lease_v1`; unknown features are refused rather than ignored.

## Channel state

```text
Cloud created and contained process
  worker -> hello
  Cloud verifies process/build/protocol/nonce
  Cloud  -> start
  worker validates all immutable bindings and initializes handlers
  worker -> ready
  execution stream begins only now
```

The default handshake deadline is one absolute 10-second deadline from process
creation through valid `ready`. `hello` is emitted before a model client, tool
executor, network client, or descendant is started. `ready` is legal only after
workspace, authority, budget, lease, parent-disconnect, containment, and cursor
validation. A crash before `ready`, timeout, or invalid frame yields no execution
and is reaped by the supervisor.

The sender's legal host-channel messages are:

| Direction | Types |
| --- | --- |
| worker -> Cloud | `hello`, `ready`, `heartbeat`, `host_action_request` |
| Cloud -> worker | `start`, `supervisor_lease`, `host_action_response` |

Cancel, pause, resume, and steer remain `aether.exec.control/2` frames. They are
not duplicated on `aether.code.host/1`.

## Common scalar rules

- IDs and nonces match `[A-Za-z0-9][A-Za-z0-9_-]{0,127}`.
- Git commit IDs are lowercase 40-hex SHA-1 values for the current repository
  contract. Executable hashes are lowercase 64-hex SHA-256 values.
- Content digests use `sha256:<lowercase-64-hex>`.
- Timestamps are UTC RFC 3339 with milliseconds, for example
  `2026-09-06T12:00:00.000Z`.
- Counts, sequences, epochs, sizes, deadlines, and budgets are safe integers;
  fields described as positive must be greater than zero.

## Message shapes

The checked-in fixtures are the canonical examples. The tables below list every
legal key; fields not listed are refused.

### `hello`

| Field | Contract |
| --- | --- |
| `protocol` | exact `aether.code.host/1` |
| `sequence` | worker sequence; zero for first hello |
| `type` | exact `hello` |
| `worker_nonce` | fresh random safe ID |
| `pid`, `pid_started_at` | positive PID and OS-correlated creation time |
| `supported_exec_protocols` | exactly `["aether.exec/2"]` in version 1 |
| `supported_features` | unique known feature names |
| `build` | exact build identity below |

`build` contains exactly `agent_git_sha`, `agent_version`,
`executable_sha256`, `publisher`, `host_protocol`, and `exec_protocol`. The
protocol values are exact `/1` and `/2` values. Cloud compares every build field
with the already verified process image and locked manifest; a structurally valid
hello is not artifact verification.

### `start`

`start` contains exactly:

- `protocol`, `sequence`, and `type`;
- `worker_nonce` echoed from hello and a fresh `main_nonce`;
- `exec_protocol` and `required_features`;
- `attempt`, `request`, `settings`, `workspace`, `lease`, `budget`,
  `credential`, and `cursors` objects.

`attempt` contains exactly:

```text
project_id, lane_id, session_id, attempt_id, generation, base_sha,
worktree_id, settings_revision, permission_profile, model, max_uvt,
authority_expires_at, lease_epoch, idempotency_key
```

The remaining objects contain exactly:

| Object | Fields |
| --- | --- |
| `request` | `task` |
| `settings` | `revision`, `values` |
| `workspace` | `canonical_root`, `repository_id`, `worktree_id`, `base_sha` |
| `lease` | `epoch`, `fence_token`, `fence_token_digest` |
| `budget` | `max_uvt`, `deadline_at`, `max_controls`, `max_steers`, `max_steer_bytes` |
| `credential` | `kind`, `audience`, `value`, `expires_at`, `single_use` |
| `cursors` | `exec_sequence`, `control_sequence` |

The repeated settings revision, worktree ID, base SHA, lease epoch, UVT ceiling,
and authority/credential expiry must be equal. They are duplicated deliberately
so each downstream gate can validate its local binding without widening it.

The only credential kind is `attempt_capability`, its audience is exactly
`aether-code-worker`, and `single_use` is true. A Cloud account/session token is
never legal. `credential.value` and `lease.fence_token` are the only usable
secrets permitted on any frame, and they are permitted only inside this private
`start` message.

### `ready`

`ready` contains exactly `protocol`, `sequence`, `type`, `attempt_id`,
`ready_digest`, `exec_protocol`, and `enabled_features`. The selected protocol
is `/2`; enabled features are known and were both advertised by hello and
required by start.

`ready_digest` is:

```text
"sha256:" + SHA256(canonical_json({
  protocol: "aether.code.host/1",
  worker_nonce, main_nonce, project_id, lane_id, session_id, attempt_id,
  generation, lease_epoch
}))
```

Canonical JSON uses sorted ASCII keys, compact separators, ASCII escaping, and
integer numeric values, matching `device_runtime/canonical_json.ts`.

### `heartbeat` and `supervisor_lease`

Worker `heartbeat` contains exactly `protocol`, `sequence`, `type`,
`attempt_id`, `lease_epoch`, `worker_state`, `last_exec_sequence`, and
`sent_at`. Worker state is one of `initializing`, `running`, `paused`,
`draining`, or `finalizing`.

Cloud `supervisor_lease` contains exactly `protocol`, `sequence`, `type`,
`attempt_id`, `lease_epoch`, `renewal_id`, and `expires_at`. Renewal does not
change attempt authority or the writer epoch. A missing renewal blocks new
actions and begins the bounded cancellation path; it never grants a new epoch.

## Host actions

`host_action_request` contains exactly `protocol`, `sequence`, `type`,
`attempt_id`, `lease_epoch`, `action_id`, `idempotency_key`, `operation`, and
`payload`. Version 1 operations and exact payload keys are:

| Operation | Payload fields |
| --- | --- |
| `repository_search` | `query`, `max_results` |
| `file_read` | `path`, `max_bytes` |
| `file_write` | `path`, `content`, `expected_sha256` (`null` means create-only) |
| `worktree_status` | none |
| `ci_command` | `check_id` |
| `user_command` | `approval_id` |
| `publish_artifact` | `artifact_ref`, `sha256`, `bytes`, `kind` |

The worker cannot choose an executable through `ci_command` or `user_command`;
Cloud resolves a predeclared check or prior explicit approval through existing
policy. Paths in requests remain subject to Cloud's canonical jail and lease
checks. Schema acceptance is never authorization.

`host_action_response` echoes attempt, epoch, action, and idempotency identity.
Its `status` selects exactly one payload:

| Status | Payload |
| --- | --- |
| `completed` | `result: { receipt_id, payload }` for a host-executed action |
| `permitted` | `permit` for one exact external command |
| `refused` | `error: { code, message, retryable }` |
| `error` | `error: { code, message, retryable }` |

An external-command `permit` contains exactly:

```text
attempt_id, action_id, lease_epoch, fence_token_digest, executable_path,
executable_file_id, executable_sha256, argv, cwd, environment, network_class,
timeout_ms, output_cap_bytes, expires_at, single_use_nonce
```

`network_class` is `denied`, `sandboxed`, or `explicit_user_authorized`.
Permits are immutable, single-use, short-lived, attempt/epoch-bound, and contain
an allowlisted environment with no credentials. A permit constrains launch and
reaping; it does not by itself prove filesystem or network sandboxing.

## Credential and diagnostic boundary

Outside the two allowed `start` paths, secret-bearing keys or recognizable
credential values fail validation. In particular, no token/capability may
appear in hello, ready, heartbeat, action payload/result/permit, controls,
stderr, argv, environment, logs, renderer state, or descendants. Production
redaction remains defense in depth; rejecting a frame is not permission to log
the rejected bytes.

The negative fixtures use conspicuous synthetic test strings only. They are not
real credentials and must remain fixed so scanners and cross-repository tests
can recognize them deterministically.

## Execution completion boundary

An `aether.exec/2` terminal frame is a candidate outcome. Process callback
ordering is not execution truth: an OS exit notification can arrive before
buffered stdout is drained. The supervisor waits for both process exit and
stdout EOF, then applies these rules:

- exactly one matching terminal frame must precede stdout EOF;
- success requires terminal `ok:true`, exit code 0, empty containment, valid
  proof, reconciled metering, closed epoch, and released worktree;
- EOF with no terminal is `LOST`, even after exit code 0;
- terminal success followed by nonzero exit is `FAILED`;
- pending metering/reconciliation remains `FINALIZING`, never early success;
- duplicate/malformed/out-of-order execution frames are protocol failures and
  can never produce success.

The fixture `completion-ordering.json` freezes both normal and reversed callback
ordering so implementations do not infer success from which event handler fires
first.

## Fixture bundle

Canonical vectors live in `contracts/aether-code/host-v1/`:

- `handshake.jsonl` — valid handshake plus timeout, crash, malformed,
  out-of-order, protocol-skew, and unknown-feature cases;
- `controls.jsonl` — `/2` control ordering, retries, limits, cancellation, and
  secret refusal;
- `host-actions.jsonl` — host-executed action, exact-command permit, stale epoch,
  and unknown-operation cases;
- `secret-boundary.jsonl` — allowed private bootstrap values and forbidden
  account token, action environment, argv, and response leakage;
- `completion-ordering.json` — terminal/EOF/exit/finalization scenarios.

JSONL records are test harness envelopes using schema
`aether.code.test-vector/1`; their `wire` member is the exact on-wire object or,
for malformed-input tests, the exact raw line. Lifecycle-only records use
`event` instead of `wire`.

`manifest.json` pins the raw-byte SHA-256 of every fixture. Its bundle digest is
SHA-256 over UTF-8 lines `path + NUL + file_sha256 + LF`, sorted by path. Both
repositories must validate the same files and bundle digest before an artifact
pin is updated.

## Explicit non-goals

Version 1 does not pool workers, multiplex attempts, add arbitrary shell/network
authority, define a second execution ledger, expose this channel to renderers,
or promise conversational context recovery. Those changes require separate,
versioned contracts and evidence.
