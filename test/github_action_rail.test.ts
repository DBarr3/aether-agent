// The Action Rail CLI's four rules, each asserted rather than documented:
// custody is always stated, approval is exact, non-interactive callers get a
// structured refusal instead of a prompt, and values stay inert typed data.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ACTION_APPROVALS,
  CLI_SCHEMA,
  CUSTODY_CLOUD,
  EXIT_AUTHORIZATION,
  EXIT_OK,
  EXIT_OPERATIONAL,
  EXIT_POLICY,
  EXIT_STALE,
  EXIT_USAGE,
  type ActionPlan,
  checkApproval,
  envelope,
  exitCodeFor,
  isMutation,
  renderPlan,
  renderReceipt,
} from "../src/core/action_rail.js";
import { parseFlags, planCommandHint } from "../src/commands/github.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");

function plan(overrides: Partial<ActionPlan> = {}): ActionPlan {
  return {
    plan_id: "plan_test_0001",
    action_digest: `sha256:${"0".repeat(64)}`,
    action_type: "aether.github.pr.create",
    project_id: "proj_alpha",
    repository: "AetherAI3/AETHER-CLOUD",
    repo: {
      repository: "AetherAI3/AETHER-CLOUD",
      base_ref: "main",
      base_sha: "a".repeat(40),
      head_ref: "feat/rate-limit",
      head_sha: "b".repeat(40),
    },
    effect_preview: "Open a draft pull request into main.",
    requested_permissions: { contents: "read", pull_requests: "write" },
    granted_permissions: { contents: "read", pull_requests: "write" },
    required_assurance: "session",
    secret_uses: [{ safe_label: "GitHub App", purpose: "open PR" }],
    budget: { max_uvt: 10, max_cost_minor: 0, currency: "USD" },
    warnings: [],
    blockers: [],
    policy_digest: `sha256:${"0".repeat(64)}`,
    expires_at: "2026-09-05T01:00:00Z",
    prepare_performed_external_writes: false,
    excludes: ["cannot merge", "cannot push commits"],
    ...overrides,
  };
}

// --- rule 1: custody is always stated ---------------------------------------

test("a rendered plan always names Aether Cloud custody", () => {
  const rendered = renderPlan(plan());
  assert.match(rendered, /Custody:\s+Aether Cloud \/ GitHub App/);
  assert.match(rendered, /not your local gh session/);
});

test("a rendered receipt always names custody too", () => {
  const rendered = renderReceipt({
    receipt_id: "rcpt_0001",
    action_type: "aether.github.pr.create",
    plan_id: "plan_test_0001",
    action_digest: `sha256:${"0".repeat(64)}`,
    repository: "AetherAI3/AETHER-CLOUD",
    provider_object_ids: { number: 7 },
    reconciled: false,
    issued_at: "2026-09-05T00:00:00Z",
  });
  assert.match(rendered, /Custody:\s+Aether Cloud \/ GitHub App/);
  assert.match(rendered, /number=7/);
});

test("the plan shows exact SHAs, not just branch names", () => {
  const rendered = renderPlan(plan());
  assert.match(rendered, new RegExp(`main @ ${"a".repeat(40)}`));
  assert.match(rendered, new RegExp(`feat/rate-limit @ ${"b".repeat(40)}`));
});

test("the plan states what the action cannot do", () => {
  const rendered = renderPlan(plan());
  assert.match(rendered, /This action CANNOT:/);
  assert.match(rendered, /cannot merge/);
});

test("the plan reports whether prepare wrote to GitHub", () => {
  assert.match(renderPlan(plan()), /Prepare wrote to GitHub: no/);
  assert.match(
    renderPlan(plan({ prepare_performed_external_writes: true })),
    /Prepare wrote to GitHub: YES/,
  );
});

test("secret uses appear by safe label only", () => {
  const rendered = renderPlan(plan());
  assert.match(rendered, /GitHub App \(open PR\)/);
  assert.ok(!/secret_ref_id/.test(rendered));
});

// --- rule 2: approval is exact ----------------------------------------------

test("the exact approval token authorizes", () => {
  assert.equal(checkApproval(plan(), "create-draft-pr", { interactive: false }), null);
});

test("a different action's approval token does not authorize", () => {
  const refusal = checkApproval(plan(), "update-pr", { interactive: false });
  assert.ok(refusal);
  assert.equal(refusal.code, "AUTH_ASSURANCE_REQUIRED");
  assert.equal(refusal.exitCode, EXIT_AUTHORIZATION);
});

for (const bogus of [
  "yes",
  "y",
  "true",
  "approve",
  "create-draft-pr ",
  "CREATE-DRAFT-PR",
  "",
]) {
  test(`a generic approval ${JSON.stringify(bogus)} does not authorize`, () => {
    const refusal = checkApproval(plan(), bogus, { interactive: false });
    assert.ok(refusal, `${JSON.stringify(bogus)} should not authorize`);
    assert.equal(refusal.exitCode, EXIT_AUTHORIZATION);
  });
}

test("a blocked plan is refused even with the right token", () => {
  const refusal = checkApproval(
    plan({ blockers: ["branch protection forbids this"] }),
    "create-draft-pr",
    { interactive: false },
  );
  assert.ok(refusal);
  assert.equal(refusal.code, "PERMISSION_DENIED");
  assert.equal(refusal.exitCode, EXIT_POLICY);
});

test("every mutating action has one distinct approval phrase", () => {
  const phrases = Object.values(ACTION_APPROVALS);
  assert.equal(new Set(phrases).size, phrases.length);
  for (const [action, phrase] of Object.entries(ACTION_APPROVALS)) {
    assert.ok(isMutation(action));
    assert.match(phrase, /^[a-z][a-z-]+$/);
  }
});

test("reads are not mutations and need no approval phrase", () => {
  for (const read of [
    "aether.github.pr.list",
    "aether.github.pr.get",
    "aether.github.checks.list",
  ]) {
    assert.equal(isMutation(read), false);
  }
});

// --- rule 3: non-interactive callers get a structured refusal ---------------

test("a missing approval in non-interactive mode refuses with authorization required", () => {
  const refusal = checkApproval(plan(), undefined, { interactive: false });
  assert.ok(refusal);
  assert.equal(refusal.code, "AUTH_ASSURANCE_REQUIRED");
  assert.match(refusal.message, /authorization required/);
  assert.match(refusal.message, /--plan plan_test_0001 --approve create-draft-pr/);
});

test("interactive mode without a confirmation still refuses", () => {
  // A TTY is not consent. The prompt has to have been answered.
  const refusal = checkApproval(plan(), undefined, { interactive: true });
  assert.ok(refusal);
  assert.equal(refusal.exitCode, EXIT_AUTHORIZATION);
});

test("an answered interactive confirmation authorizes", () => {
  assert.equal(
    checkApproval(plan(), undefined, { interactive: true, confirmed: true }),
    null,
  );
});

// --- rule 4: values stay inert typed data -----------------------------------

test("a value that looks like a flag is taken as a value", () => {
  const { flags } = parseFlags(["--title", "--force"]);
  assert.equal(flags["title"], "--force");
});

for (const hostile of [
  "$(rm -rf ~)",
  "`whoami`",
  "a; rm -rf /",
  "line1\nline2",
  'quote" and \'quote',
  "C:\\Windows\\System32",
  "--approve create-draft-pr",
  "|| true",
]) {
  test(`hostile value ${JSON.stringify(hostile)} survives as an inert string`, () => {
    const { flags } = parseFlags(["--title", hostile]);
    assert.equal(flags["title"], hostile, "value must not be reinterpreted");
  });
}

test("a trailing flag with no value is recorded empty, not swallowed", () => {
  const { flags } = parseFlags(["--title"]);
  assert.equal(flags["title"], "");
});

test("boolean flags do not consume the next token", () => {
  const { bools, flags } = parseFlags(["--draft", "--repo", "o/n"]);
  assert.ok(bools.has("draft"));
  assert.equal(flags["repo"], "o/n");
});

test("positionals are kept in order", () => {
  const { positional } = parseFlags(["7", "--repo", "o/n", "extra"]);
  assert.deepEqual(positional, ["7", "extra"]);
});

// --- no local gh, ever ------------------------------------------------------

for (const relative of ["src/core/action_rail.ts", "src/commands/github.ts"]) {
  test(`${relative} never spawns a process`, () => {
    const source = readFileSync(join(repoRoot, relative), "utf8");
    for (const forbidden of [
      "child_process",
      "execSync",
      "spawnSync",
      "execFile",
    ]) {
      assert.ok(
        !source.includes(forbidden),
        `${relative} must not reference ${forbidden}: Cloud custody never shells out to gh`,
      );
    }
  });
}

test("the help text never offers a forbidden capability", () => {
  const source = readFileSync(join(repoRoot, "src/commands/github.ts"), "utf8");
  const help = source.slice(source.indexOf("function printGithubHelp"));
  for (const forbidden of ["merge", "force-push", "delete-branch", "secrets set"]) {
    const offered = new RegExp(`aether github [a-z ]*${forbidden}`, "i");
    assert.ok(!offered.test(help), `help must not offer ${forbidden}`);
  }
});

// --- stable machine surface -------------------------------------------------

test("the JSON envelope has a stable shape and default custody", () => {
  const value = envelope({ command: "github.pr.prepare", status: "prepared" });
  assert.equal(value.schema, CLI_SCHEMA);
  assert.equal(value.custody, CUSTODY_CLOUD);
  assert.deepEqual(Object.keys(value).sort(), [
    "command",
    "custody",
    "error",
    "grant",
    "plan",
    "project_id",
    "receipt",
    "schema",
    "status",
  ]);
});

test("the envelope carries no ANSI escapes", () => {
  const serialized = JSON.stringify(
    envelope({ command: "github.pr.prepare", status: "prepared", plan: plan() }),
  );
  assert.ok(!serialized.includes("\u001b["));
});

test("data is omitted rather than null when there is none", () => {
  assert.ok(!("data" in envelope({ command: "github.pr.create" })));
  assert.ok("data" in envelope({ command: "github.pr.list", data: [] }));
});

// --- stable exits -----------------------------------------------------------

test("exit codes map the way a script expects", () => {
  assert.equal(exitCodeFor("UNAUTHENTICATED"), EXIT_AUTHORIZATION);
  assert.equal(exitCodeFor("AUTH_ASSURANCE_REQUIRED"), EXIT_AUTHORIZATION);
  assert.equal(exitCodeFor("ACTION_HEAD_STALE"), EXIT_STALE);
  assert.equal(exitCodeFor("REPLAY_DETECTED"), EXIT_STALE);
  assert.equal(exitCodeFor("BUDGET_EXCEEDED"), EXIT_POLICY);
  assert.equal(exitCodeFor("INVALID_ARGUMENT"), EXIT_USAGE);
  assert.equal(exitCodeFor("PROVIDER_UNAVAILABLE"), EXIT_OPERATIONAL);
});

test("an unknown error code never reports success", () => {
  assert.notEqual(exitCodeFor("SOMETHING_A_NEWER_SERVER_SAYS"), EXIT_OK);
});

test("the prepare hint names the command that runs the plan", () => {
  assert.equal(planCommandHint("aether.github.pr.create"), "pr create");
  assert.equal(planCommandHint("aether.github.ci.rerun_failed"), "ci rerun");
  assert.equal(planCommandHint("aether.github.workflow.dispatch"), "workflow dispatch");
});
