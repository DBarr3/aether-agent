// action_rail.ts — the client half of the Cloud GitHub Action Rail.
//
// The rail's contract is prepare -> preview -> authorize -> execute -> receipt.
// This module owns the CLI's side of it: typed calls, human plan rendering, a
// stable JSON envelope, and the approval rules that decide whether a mutation
// may run at all.
//
// FOUR RULES, EACH ONE A TEST IN test/github_action_rail.test.ts:
//
//  1. Custody is always stated. Every plan, confirmation, receipt and error
//     says whose credentials are about to be used. `aether github ...` is
//     ALWAYS Aether Cloud custody — the backend's GitHub App, a JIT token, and
//     an ActionRun. This module never invokes a local `gh` binary and never
//     touches the user's own GitHub session. There is no fallback between the
//     two custody models, because a silent fallback is how someone believes
//     they published under one identity and actually published under another.
//
//  2. A mutation needs the exact stored plan AND the exact action-specific
//     approval token. `--yes` is not authority. A generic `--approve` is not
//     authority. `--approve create-draft-pr` authorizes creating a draft pull
//     request and nothing else, so an approval typed for one action cannot be
//     replayed against a different one.
//
//  3. Non-interactive callers get a structured refusal, never a prompt. A model
//     or a script that asks for a mutation without a plan receives
//     AUTHORIZATION_REQUIRED plus the plan to show a human. It does not hang
//     waiting on a TTY that isn't there, and it cannot confirm on the human's
//     behalf.
//
//  4. Values stay typed data. Nothing here builds a shell string, and no
//     caller-supplied value is ever re-parsed. A title of `--force` or
//     `$(rm -rf ~)` is an inert string in a JSON body — the same discipline
//     src/core/review_actions.ts applies to paths, for the same reason.

import type { ApiClient } from "./transport.js";

/** Whose credentials perform the operation. Rendered on every surface. */
export const CUSTODY_CLOUD = "aether_cloud_github_app";
export const CUSTODY_LOCAL = "local_user_gh";

export const CLI_SCHEMA = "aether.cli.github/1";

/**
 * Stable process exits. A script branches on these; changing one is a breaking
 * change to every caller that ever wrote `if [ $? -eq 3 ]`.
 */
export const EXIT_OK = 0;
export const EXIT_OPERATIONAL = 1;
export const EXIT_USAGE = 2;
export const EXIT_AUTHORIZATION = 3;
export const EXIT_STALE = 4;
export const EXIT_POLICY = 5;

/**
 * action_type -> the exact --approve value that authorizes it.
 *
 * Deliberately not derived from the action name by transformation. A mapping a
 * reader can check by eye is worth more here than one that is clever, and a
 * generated token would let a new action silently inherit an approval phrase a
 * user has already been trained to type.
 */
export const ACTION_APPROVALS: Readonly<Record<string, string>> = Object.freeze({
  "aether.github.pr.create": "create-draft-pr",
  "aether.github.pr.update": "update-pr",
  "aether.github.ci.rerun_failed": "rerun-failed-checks",
  "aether.github.workflow.dispatch": "dispatch-workflow",
});

/** Read-only intents. Never require an approval token. */
export const READ_ACTIONS: readonly string[] = Object.freeze([
  "aether.github.pr.list",
  "aether.github.pr.get",
  "aether.github.pr.prepare",
  "aether.github.checks.list",
]);

export interface RailRepo {
  repository: string;
  base_ref: string;
  base_sha: string;
  head_ref: string;
  head_sha: string;
}

export interface ActionPlan {
  plan_id: string;
  action_digest: string;
  action_type: string;
  project_id: string;
  repository: string;
  repo?: RailRepo | null;
  effect_preview: string;
  requested_permissions: Record<string, string>;
  granted_permissions: Record<string, string>;
  required_assurance: string;
  secret_uses: Array<{ safe_label: string; purpose: string }>;
  budget: { max_uvt: number; max_cost_minor: number; currency: string };
  warnings: string[];
  blockers: string[];
  policy_digest: string;
  expires_at: string;
  /** The rail asserts this; the CLI renders it rather than assuming it. */
  prepare_performed_external_writes: boolean;
  /** Operator-facing statement of what this action cannot do. */
  excludes?: string[];
}

export interface ActionReceipt {
  receipt_id: string;
  action_type: string;
  plan_id: string;
  action_digest: string;
  repository: string;
  provider_object_ids: Record<string, string | number>;
  reconciled: boolean;
  issued_at: string;
}

export interface RailError {
  schema: string;
  code: string;
  message: string;
  request_id?: string;
  retryable?: boolean;
}

export interface CliEnvelope {
  schema: string;
  command: string;
  custody: string;
  status: "ok" | "prepared" | "executed" | "authorization_required" | "error";
  project_id: string | null;
  plan: ActionPlan | null;
  grant: { grant_id: string } | null;
  receipt: ActionReceipt | null;
  error: RailError | null;
  /** Read results (PR lists, checks). Absent for mutations. */
  data?: unknown;
}

export class RailRefusal extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly exitCode: number,
  ) {
    super(message);
  }
}

/**
 * Map a stable rail error code to a process exit.
 *
 * Unknown codes exit OPERATIONAL rather than OK. A code this build has never
 * heard of is a newer server telling us something went wrong, and reporting
 * success because we did not recognise the complaint is the worst option.
 */
export function exitCodeFor(code: string): number {
  switch (code) {
    case "UNAUTHENTICATED":
    case "AUTH_ASSURANCE_REQUIRED":
    case "PERMISSION_DENIED":
      return EXIT_AUTHORIZATION;
    case "ACTION_HEAD_STALE":
    case "POLICY_STALE":
    case "ACTION_DIGEST_MISMATCH":
    case "ACTION_GRANT_CONSUMED":
    case "ACTION_GRANT_EXPIRED":
    case "ACTION_GRANT_REVOKED":
    case "REPLAY_DETECTED":
      return EXIT_STALE;
    case "BUDGET_EXCEEDED":
    case "SECRET_USE_NOT_ALLOWED":
      return EXIT_POLICY;
    case "INVALID_ARGUMENT":
    case "INVALID_SCHEMA":
      return EXIT_USAGE;
    default:
      return EXIT_OPERATIONAL;
  }
}

export function isMutation(actionType: string): boolean {
  return Object.prototype.hasOwnProperty.call(ACTION_APPROVALS, actionType);
}

/**
 * Decide whether a mutation may proceed.
 *
 * Returns null when authorized. Otherwise returns the refusal to render — the
 * caller does not get a boolean, because "not authorized" needs to carry WHY in
 * a form a script can branch on.
 */
export function checkApproval(
  plan: ActionPlan,
  approve: string | undefined,
  opts: { interactive: boolean; confirmed?: boolean },
): RailRefusal | null {
  const expected = ACTION_APPROVALS[plan.action_type];
  if (!expected) {
    return new RailRefusal(
      "INVALID_ARGUMENT",
      `${plan.action_type} is not an approvable action`,
      EXIT_USAGE,
    );
  }
  if (plan.blockers.length > 0) {
    return new RailRefusal(
      "PERMISSION_DENIED",
      `plan is blocked: ${plan.blockers.join("; ")}`,
      EXIT_POLICY,
    );
  }
  if (approve !== undefined) {
    // Exact match. A prefix, a different action's phrase, or `--approve yes`
    // is not this action's approval.
    if (approve !== expected) {
      return new RailRefusal(
        "AUTH_ASSURANCE_REQUIRED",
        `--approve ${expected} is required for ${plan.action_type} ` +
          `(got ${JSON.stringify(approve)})`,
        EXIT_AUTHORIZATION,
      );
    }
    return null;
  }
  if (opts.interactive && opts.confirmed === true) return null;
  return new RailRefusal(
    "AUTH_ASSURANCE_REQUIRED",
    opts.interactive
      ? `confirmation required: re-run with --plan ${plan.plan_id} --approve ${expected}`
      : `authorization required: re-run with --plan ${plan.plan_id} --approve ${expected}`,
    EXIT_AUTHORIZATION,
  );
}

/** The stable machine surface. No ANSI, no prose, no stderr chatter. */
export function envelope(
  partial: Partial<CliEnvelope> & { command: string },
): CliEnvelope {
  return {
    schema: CLI_SCHEMA,
    command: partial.command,
    custody: partial.custody ?? CUSTODY_CLOUD,
    status: partial.status ?? "ok",
    project_id: partial.project_id ?? null,
    plan: partial.plan ?? null,
    grant: partial.grant ?? null,
    receipt: partial.receipt ?? null,
    error: partial.error ?? null,
    ...(partial.data === undefined ? {} : { data: partial.data }),
  };
}

function permissionLine(permissions: Record<string, string>): string {
  const entries = Object.entries(permissions).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) return "none";
  return entries.map(([name, level]) => `${name}:${level}`).join(", ");
}

/**
 * Render the plan a human is being asked to approve.
 *
 * Shows the exact SHAs rather than branch names alone: a branch name is a label
 * that can move between the moment this is printed and the moment it executes,
 * and the whole point of the plan is that it is bound to a commit.
 */
export function renderPlan(plan: ActionPlan): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`Action:      ${plan.action_type}`);
  lines.push("Custody:     Aether Cloud / GitHub App  (not your local gh session)");
  lines.push(`Project:     ${plan.project_id}`);
  lines.push(`Repository:  ${plan.repository}`);
  if (plan.repo) {
    lines.push(`Base:        ${plan.repo.base_ref} @ ${plan.repo.base_sha}`);
    lines.push(`Head:        ${plan.repo.head_ref} @ ${plan.repo.head_sha}`);
  }
  lines.push(`Effect:      ${plan.effect_preview}`);
  lines.push(`Permissions: ${permissionLine(plan.requested_permissions)}`);

  const requested = permissionLine(plan.requested_permissions);
  const granted = permissionLine(plan.granted_permissions);
  if (requested !== granted) lines.push(`  granted now: ${granted}`);

  if (plan.secret_uses.length > 0) {
    lines.push("Credentials:");
    for (const use of plan.secret_uses) {
      lines.push(`  - ${use.safe_label} (${use.purpose})`);
    }
  }
  lines.push(
    `Budget:      max ${plan.budget.max_uvt} UVT / ` +
      `${plan.budget.max_cost_minor} ${plan.budget.currency} minor units`,
  );
  lines.push(`Assurance:   ${plan.required_assurance}`);
  lines.push(`Policy:      ${plan.policy_digest}`);
  lines.push(`Digest:      ${plan.action_digest}`);
  lines.push(`Plan:        ${plan.plan_id}  (expires ${plan.expires_at})`);
  lines.push(
    `Prepare wrote to GitHub: ${
      plan.prepare_performed_external_writes ? "YES — REPORT THIS" : "no"
    }`,
  );

  if (plan.excludes && plan.excludes.length > 0) {
    lines.push("This action CANNOT:");
    for (const exclude of plan.excludes) lines.push(`  - ${exclude}`);
  }
  for (const warning of plan.warnings) lines.push(`Warning:     ${warning}`);
  for (const blocker of plan.blockers) lines.push(`BLOCKED:     ${blocker}`);
  lines.push("");
  return lines.join("\n");
}

export function renderReceipt(receipt: ActionReceipt): string {
  const ids = Object.entries(receipt.provider_object_ids)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join(" ");
  const lines = [
    "",
    `Done:     ${receipt.action_type}`,
    "Custody:  Aether Cloud / GitHub App",
    `Repo:     ${receipt.repository}`,
    ids ? `Result:   ${ids}` : "Result:   (no provider identifiers returned)",
  ];
  if (receipt.reconciled) {
    lines.push("Note:     reconciled after a lost provider response");
  }
  lines.push(`Receipt:  ${receipt.receipt_id}`);
  lines.push("");
  return lines.join("\n");
}

// --- transport --------------------------------------------------------------
//
// Typed methods only. Every value crosses as JSON; nothing is interpolated into
// a path without encodeURIComponent, and no method here shells out.

export const RAIL_BASE = "/cloud/actions/github";

export interface PrepareRequest {
  project_id: string;
  action_type: string;
  inputs: Record<string, unknown>;
}

export async function prepare(api: ApiClient, body: PrepareRequest): Promise<ActionPlan> {
  return api.postJson<ActionPlan>(`${RAIL_BASE}/prepare`, body);
}

export async function execute(
  api: ApiClient,
  body: { plan_id: string; action_digest: string; approve: string },
): Promise<{ receipt: ActionReceipt }> {
  return api.postJson<{ receipt: ActionReceipt }>(`${RAIL_BASE}/execute`, body);
}

export async function listPullRequests(
  api: ApiClient,
  params: { project_id: string; repository: string },
): Promise<unknown> {
  const query = new URLSearchParams({
    project_id: params.project_id,
    repository: params.repository,
  });
  return api.getJson<unknown>(`${RAIL_BASE}/pull-requests?${query.toString()}`);
}

export async function getPullRequest(
  api: ApiClient,
  params: { project_id: string; repository: string; number: number },
): Promise<unknown> {
  const query = new URLSearchParams({
    project_id: params.project_id,
    repository: params.repository,
  });
  return api.getJson<unknown>(
    `${RAIL_BASE}/pull-requests/${encodeURIComponent(String(params.number))}` +
      `?${query.toString()}`,
  );
}

export async function listChecks(
  api: ApiClient,
  params: { project_id: string; repository: string; number: number },
): Promise<unknown> {
  const query = new URLSearchParams({
    project_id: params.project_id,
    repository: params.repository,
    pull_request: String(params.number),
  });
  return api.getJson<unknown>(`${RAIL_BASE}/checks?${query.toString()}`);
}

export async function getAction(api: ApiClient, actionId: string): Promise<unknown> {
  return api.getJson<unknown>(`${RAIL_BASE}/actions/${encodeURIComponent(actionId)}`);
}
