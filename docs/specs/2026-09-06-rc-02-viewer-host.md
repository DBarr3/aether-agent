# RC-02 — Agent Remote Control viewer host

**Status:** specification, not yet implemented
**Lane:** `RC-02` · branch `feat/rc-viewer-current-main`
**Repository:** `AetherAI3/aether-agent`
**Base at writing:** `main` @ `26b27411dec8ffaf97525c4318011a07ba856744`
**Program:** Aether Control Plane P0 — the last unstarted lane

---

## 1. What this lane is, in one paragraph

The Agent gains an **outbound-only observation host**: it publishes structured,
redacted events about what a local session is doing so an authenticated viewer
can watch it in the Cloud Live Cockpit. It opens no listening socket, accepts no
inbound command, and continues working normally when the broker is unreachable,
the viewer disconnects, or the session is revoked. It is the producer half of
the viewer contract whose consumer half already landed Cloud-side.

**It is not remote control.** Nothing here accepts a prompt, a keystroke, a
shell command, an approval, or a pause. That is `RC-CTRL`, a separate train
behind a separate gate, and this lane must not leave a dormant path toward it.

---

## 2. Verified starting truth

Everything in this section was checked against `main` @ `26b27411`, not assumed.

### 2.1 There is no RC code on `main`

`git ls-tree -r origin/main | grep -iE "remote|/rc\.|qr\."` returns **nothing**.
There is no module to extend. Every file this lane adds is new, and PR #108 is
the only existing source of the behaviour.

### 2.2 Device enrollment exists and is the canonical identity

`src/core/device_runtime/` is present and complete enough to be the identity
source: `identity.ts`, `enablement.ts`, `contract.ts`, `daemon.ts`,
`daemon_state.ts`, `containment.ts`, `registry.ts`, `net.ts`, `paths.ts`.

`identity.ts` exports `EnrollmentRecord`, `loadEnrollment()`,
`saveEnrollment()`, `clearEnrollment()`, `resolveBootIdentity()`.

**The gap this lane must close first.** `EnrollmentRecord` is:

```ts
{ device_id, device_token, device_command_key, base_url, enrolled_at, display_name }
```

and `loadEnrollment()` returns all of it. There is **no metadata-only
accessor**. RC needs `device_id` and `display_name` to identify a session; it
must never hold `device_token` or `device_command_key`. Calling
`loadEnrollment()` from RC code would pull both into a process that publishes
events, which is precisely the custody failure this program exists to prevent.

### 2.3 Two P0 lanes already landed here and must be used

- `src/core/child_env.ts` (CF-02) — deny-by-default child environments,
  `SENSITIVE_KEY` reuse, `findCredentials`, `custodyReport`. Any process RC
  spawns uses this; RC adds no new launcher that spreads `process.env`.
- `src/core/action_rail.ts` (UX-01) — the typed Cloud client pattern, the stable
  `aether.cli.*` envelope, and the exit-code map. RC's CLI output follows that
  shape rather than inventing a second one.

### 2.4 The Cloud consumer half already merged

`AETHER-CLOUD` `lib/remote_session/viewer_profile.py` (RC-01, merged
`39a16029`) defines the closed viewer surface: `VIEWER_CAPABILITIES ==
("observe",)`, `VIEWER_EVENT_TYPES` (a strict subset of `EVENT_TYPES`,
excluding `transcript`), `VIEWER_PRESENCE_ROLES` without `controller`, and
`FORBIDDEN_VIEWER_TERMS` with a camelCase/snake_case-aware tokenizer.

**The host mirrors that projection; it does not restate it.** Where the two
could drift, the Agent's fixture is generated from the Cloud manifest, so a
divergence fails a test rather than shipping.

### 2.5 PR #108 — current state, verified

| Field | Value |
|---|---|
| State | OPEN, **draft** |
| Head | `c7ac06d8` |
| Base | `main` |
| Merge state | **`DIRTY`** (conflicts) |
| Changed files | **75** |
| Last updated | 2026-08-28 |

Do **not** merge, rebase, `gh pr checkout`, or cherry-pick it. Of those 75
files, the large majority are CI workflows, release machinery, generated docs,
the model catalogue, and unrelated command churn — none of which belongs in this
lane.

---

## 3. Provenance and rejection map

The successor PR must carry this table. Spec §10 requires it, and it is the
artifact that makes "we ported it deliberately" checkable rather than claimed.

### 3.1 Commits to port by hand

| Commit | Behaviour | Disposition |
|---|---|---|
| `b4e45de` | initial RC host | **port, refit** — see §5.1, §5.2 |
| `827a273` | broker route reconciliation | **port** — keeps host/broker route agreement |
| `2dbf499` | device ID and per-event receipts | **port receipts, REJECT the device ID** — §5.1 |
| `8e261a9` | durable revocation tombstone | **port, refit** — §5.4 |
| `c7ac06d` | ambiguous broker response / outbox preservation | **port, refit** — §5.3 |

### 3.2 Files to port

```
src/core/remote_host.ts
src/core/remote_redaction.ts
src/commands/rc.ts
src/ui/qr.ts
test/rc_host.test.ts
test/rc_redaction.test.ts
test/rc_command.test.ts
```

### 3.3 Explicitly rejected

- The synthetic `dev_<uuid>` device identity (§5.1).
- Generated docs, release machinery, CI workflow edits, model-catalogue and
  preview changes, and unrelated command churn.
- Any event type, payload key, or route carrying control or steer vocabulary.
- `transcript` as a shipped event type (§6.2).

---

## 4. Non-negotiable boundaries

1. **Outbound only.** The host opens no listening socket and binds no port.
2. **No inbound anything.** No command queue, no polling route, no prompt or
   approval submission, no keyboard/mouse/terminal/shell/file/env/clipboard
   input, no pause/resume/checkpoint/restart/terminate, no dormant controller
   path.
3. **Local work is never affected.** Broker outage, viewer disconnect, grant
   expiry, Cloud outage, and revocation each leave the local session running
   normally. RC failure degrades observation, never execution.
4. **No raw credential on disk or in output.** The host persists a
   `host_secret_ref`, never a host secret, device token, or command key.
5. **Enrollment is identity, not permission.** Being enrolled lets RC name the
   device; it does not enable the command daemon, and `aether device disable`
   is not server-side revocation and must never be labelled as such.

---

## 5. Required refits to PR #108

Thirteen, from master spec §10. The four load-bearing ones are stated first,
because they are the ones a port would most plausibly skip.

### 5.1 Canonical enrollment, not a synthetic device ID

PR #108 defaults to `dev_<uuid>`. That is a self-asserted string: anyone can
mint one, so it authenticates nothing.

**Required.** RC start demands an authenticated Aether account and a canonical,
enrolled, non-revoked device. Add to `src/core/device_runtime/identity.ts`:

```ts
export interface EnrollmentMetadata {
  device_id: string;
  display_name?: string;
  base_url: string;
  enrolled_at?: string;
}

/** Identity and display fields ONLY. Never returns device_token or
 *  device_command_key — RC publishes events and must not hold either. */
export function loadEnrollmentMetadata(): EnrollmentMetadata | null;
```

RC imports **only** this. A test asserts `remote_host.ts` and `rc.ts` never
reference `loadEnrollment`, `device_token`, or `device_command_key` — the same
source-reading technique `test/child_env.test.ts` already uses to prove the four
launchers stopped spreading `process.env`.

Device runtime **enablement is not required to observe**. Enrollment is
identity; enabling the command daemon is a separate operator choice.

### 5.2 Host credential into custody, or do not activate

On first start the Cloud issues a host credential.

**Required order.** Deposit it into native/brokered custody *immediately*,
persist only `host_secret_ref`, and resolve it just-in-time inside the
attach/heartbeat/append/revoke transport. Command and UI code never see it.

**If custody fails, do not activate.** Best-effort revoke the newly created
Cloud session, then return a clear inert failure. A host that runs with a
credential it could not store safely is worse than a host that did not start,
because the operator believes custody succeeded.

### 5.3 Receipts are a complete, ordered, one-to-one batch

The cursor advances **only** on a complete typed acceptance receipt. Preserve
the entire batch on: any duplicate event ID, any decreasing or stale sequence, a
sequence not greater than the durable cursor, a missing item, a mismatched
payload digest, a partial receipt, a generic 409, a malformed body, a timeout
after send, or an unknown rejection.

Resending the same `host_event_id` with different bytes is
`RC_EVENT_ID_CONFLICT` — the event ID binds the payload digest.

### 5.4 A failed `revoke_pending` write is a hard local quarantine

`aether rc off` is local-first and server-final:

1. Stop local publication and new queue entries immediately.
2. Destroy in-memory RC capabilities.
3. Persist `revoke_pending` **before** the network request.
4. Cloud atomically revokes session/grants/host credentials, advances the epoch,
   closes streams, emits a redacted receipt.
5. Delete local state and the RC SecretRef **only** after confirmed Cloud
   revocation.
6. If Cloud is unreachable: stay locally off, retain the minimal
   tombstone/reference, refuse automatic resume, retry safely later.

If step 3's durable write fails, stop publication, refuse automatic attach, and
never report revocation as completed.

### 5.5 The remaining nine

| # | Refit |
|---|---|
| 6 | One RC event adapter wired into current session/workflow events — not per-renderer edits |
| 7 | Current command manifest/registry conventions; one implementation for CLI and slash surfaces |
| 8 | Every host/event request binds ProjectContext, session epoch, enrolled device, protocol and redaction versions |
| 9 | On startup, schema-validate, bound, and re-scan every persisted outbox item before it can be resent; quarantine or discard invalid entries behind a visible counter |
| 10 | Normalize viewer/redemption/CI/PR/artifact URLs through a safe projection: allowed HTTPS origin and path plus approved public identifiers; strip or reject userinfo, credential-like query values, fragments, and unexpected origins **before persistence or display** |
| 11 | Preserve local-first failure semantics, outbox durability, dedupe, typed per-item receipts, revocation tombstones |
| 12 | Wire real structured producers for plan, subagent, tool, diff summary, test, CI, PR, artifact, preview, completion and safe errors — **a declared event type with no producer is not a delivered feature** |
| 13 | Reloaded durable state is untrusted input: apply the same schema, allowlist, bounds, URL projection, path rules and credential scan after restart that applied before first enqueue |

---

## 6. The event plane

### 6.1 Properties to keep from PR #108

Sanitize before durable enqueue · persist before send · per-project durable
cursor and outbox · at-least-once upload with `host_event_id` dedupe ·
payload-bound idempotency · typed per-item receipts · one exclusive host ·
exponential retry 1–60 s with jitter · bounded batch and storage · visible drops
and gaps.

### 6.2 Bounds

```
32       events per append
1,000    events maximum local outbox
32 KiB   maximum canonical payload
1 KiB    maximum string
64       maximum list items
15 s     host heartbeat
```

Each event binds: schema/version, session and epoch, enrolled device, host event
ID, monotonic host sequence, event type, creation time, redaction profile,
payload digest, optional observed repo/head.

Event classes mirror `viewer_profile.VIEWER_EVENT_TYPES`. **`transcript` is
excluded**: v1 is a structured-event view, and bounded transcript summaries
require a per-session exposure choice that does not exist yet. Shipping the type
before that choice exists makes "can a viewer read my prompts?" depend on which
producer happened to be wired.

### 6.3 Always rejected

Unknown event types and keys, arbitrary nested objects, absolute or external
paths, environment values, credentials, authorization headers, SecretRefs,
cookies, raw file or diff bodies, shell history, stdin/stdout/stderr, browser
DOM/storage/screenshots, hidden or system prompts, private Memory, Vault
content.

Agent applies the allowlist and scanner **before durable storage**. Cloud
independently validates schema, size and order, scans again, rate-limits, and
rejects before persistence. Two scanners on one boundary is deliberate.

---

## 7. Command surface

```
aether rc start [--name <name>]
aether rc status
aether rc exposure
aether rc viewers
aether rc off
```

Registered through the existing manifest at
`src/commands/command_manifest_data.ts` — one entry owning help, aliases, flags,
permissions, telemetry name and disposition — then `npm run docs:generate`.
Never hand-edit `docs/generated/`.

**Two manifest traps, both hit during UX-01:**

1. `scripts/generate-docs.ts` holds a `COMMAND_PLACEHOLDERS` allowlist. A new
   `<a|b|c>` args string must be added there or the markdown-injection guard
   rejects the whole generation.
2. `--json` is a global flag parsed in `main.ts`; a command that needs it must be
   passed it explicitly.

`status` and `exposure` show viewer-only mode, enrolled device, session, project,
repo, branch, observed head, state, expiry, observer count, exposed categories,
pending/acked/dropped counts, and the literal line **"No terminal or tool
control"**. They never print credentials, SecretRefs, or redemption values.

---

## 8. Exit proof

A lane is done when these pass at the exact PR head — not when it compiles.

| # | Proof |
|---|---|
| 1 | Exact current-main base recorded; provenance table (§3) attached; PR opens with `Supersedes #108` |
| 2 | Route/tool/schema/help manifest contains **zero** control or steer vocabulary, checked with the Cloud tokenizer's rules (snake_case, camelCase, PascalCase, dotted, kebab, SCREAMING_SNAKE) |
| 3 | Source-read test: no RC module references `loadEnrollment`, `device_token`, or `device_command_key` |
| 4 | Enrolled / revoked / unknown / not-enrolled device cases each behave correctly |
| 5 | Custody failure at start ⇒ host inert, Cloud session best-effort revoked, clear error |
| 6 | No raw credential on disk or in any output, asserted by seeded-canary scan |
| 7 | Every payload in a hostile control corpus is rejected before dispatch |
| 8 | Cross-tenant / project / device / session / epoch access fails closed |
| 9 | Redaction, size, nesting, path and credential fuzz pass |
| 10 | 90-second broker outage: local session completes unaffected; no duplicate events displayed after reconnect |
| 11 | Partial, malformed, generic-409, timeout-after-send and out-of-order receipts each preserve the full batch |
| 12 | Restart with a poisoned outbox: invalid entries quarantined behind a visible counter, never resent |
| 13 | Offline `rc off` stays off, refuses auto-resume, reconciles later |
| 14 | No listening socket opened, asserted at runtime |
| 15 | Existing suites green on ubuntu **and** windows (CI is authoritative — the full `npm test` exceeds a 10-minute local window) |

---

## 9. Explicitly out of scope

Bounded RC control (`RC-CTRL`) in every form — command registry, controller
grants, pause/resume/checkpoint/cancel/emergency-stop, process-group targeting.
It is a separate train behind the entry gate in §11 of the master specification,
and it requires device-revocation SLO proof, passkey step-up bound to an exact
action digest, containment identity, and concurrency proof that this lane does
not attempt.

Browser takeover, human input leases, and `browser.input` are likewise separate.

---

## 10. Operating notes for whoever picks this up

- Re-resolve `main` at dispatch. `26b27411` is a timestamp, not a target.
- Work in a worktree. The primary checkout sits on a stale branch, and reading
  files there gave a wrong answer during UX-01 — a 48-line `cli_registry.ts`
  where main's is 313.
- Worktrees need their own `npm ci`; there is no shared `node_modules`.
- CI is the authority for the full suite. Locally, run the targeted files.
- `SENSITIVE_KEY` in `src/core/redaction.ts` contains `pat` and is
  case-insensitive, so it matches `PATH`. Fine for its hex-value consumers, a
  false positive if used to classify bare environment variable names — see
  `child_env.ts` for the reviewed-name exemption.

Aether AI LLC — Patent Pending
