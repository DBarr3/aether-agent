import { createHash } from "node:crypto";
import { canonicalJson } from "./device_runtime/canonical_json.js";
import {
  HEADLESS_CONTROL_PROTOCOL_V2,
  parseControlFrame,
  type ControlFrame,
} from "./headless_protocol.js";

export const AETHER_CODE_HOST_PROTOCOL = "aether.code.host/1" as const;
export const AETHER_CODE_EXEC_PROTOCOL = "aether.exec/2" as const;
export const AETHER_CODE_CONTROL_PROTOCOL = HEADLESS_CONTROL_PROTOCOL_V2;
export const AETHER_CODE_HOST_MAX_FRAME_BYTES = 64 * 1024;
export const AETHER_CODE_HOST_FEATURES = ["host_actions_v1", "supervisor_lease_v1"] as const;

export type AetherCodeHostDirection = "worker_to_host" | "host_to_worker";
export type AetherCodeHostMessageType =
  | "hello"
  | "start"
  | "ready"
  | "heartbeat"
  | "supervisor_lease"
  | "host_action_request"
  | "host_action_response";

export type AetherCodeHostValidationCode =
  | "FRAME_TOO_LARGE"
  | "MALFORMED_JSON"
  | "INVALID_FRAME"
  | "UNKNOWN_FIELD"
  | "WRONG_DIRECTION"
  | "UNSUPPORTED_HOST_PROTOCOL"
  | "UNSUPPORTED_EXEC_PROTOCOL"
  | "UNKNOWN_FEATURE"
  | "SECRET_EXPOSURE"
  | "FULL_SESSION_TOKEN_FORBIDDEN";

export interface AetherCodeHostValidationError {
  code: AetherCodeHostValidationCode;
  message: string;
}

export type AetherCodeHostValidationResult<T = Record<string, unknown>> =
  | { ok: true; value: T }
  | { ok: false; error: AetherCodeHostValidationError };

export interface AetherCodeReadyDigestInput {
  worker_nonce: string;
  main_nonce: string;
  project_id: string;
  lane_id: string;
  session_id: string;
  attempt_id: string;
  generation: number;
  lease_epoch: number;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const SHA1 = /^[a-f0-9]{40}$/;
const SHA256_TAGGED = /^sha256:[a-f0-9]{64}$/;
const HOST_TYPES = new Set<AetherCodeHostMessageType>([
  "hello",
  "start",
  "ready",
  "heartbeat",
  "supervisor_lease",
  "host_action_request",
  "host_action_response",
]);
const WORKER_TYPES = new Set<AetherCodeHostMessageType>([
  "hello",
  "ready",
  "heartbeat",
  "host_action_request",
]);
const MAIN_TYPES = new Set<AetherCodeHostMessageType>([
  "start",
  "supervisor_lease",
  "host_action_response",
]);
const ACTIONS = new Set([
  "repository_search",
  "file_read",
  "file_write",
  "worktree_status",
  "ci_command",
  "user_command",
  "publish_artifact",
]);
const SENSITIVE_KEY = /(?:token|secret|password|passwd|authorization|api[_-]?key|access[_-]?key|private[_-]?key|credential|cookie|\bpat\b)/i;
const SENSITIVE_VALUE = /(?:\bBearer\s+[A-Za-z0-9._~-]{8,}|\bsk-[A-Za-z0-9_-]{8,}|\bgh[opusr]_[A-Za-z0-9_]{8,}|\bgithub_pat_[A-Za-z0-9_]{8,}|\bnpm_[A-Za-z0-9]{8,}|\bpypi-[A-Za-z0-9_-]{8,}|\bxox[baprs]-[A-Za-z0-9-]{8,}|--(?:password|passwd|token|api[_-]?key|secret)(?:=|\s+)\S+)/i;
const ALLOWED_SENSITIVE_KEYS = new Set([
  "credential",
  "credential.value",
  "lease.fence_token",
  "lease.fence_token_digest",
  "permit.fence_token_digest",
]);
const ALLOWED_SENSITIVE_VALUES = new Set(["credential.value", "lease.fence_token"]);

function pass<T>(value: T): AetherCodeHostValidationResult<T> {
  return { ok: true, value };
}

function fail(code: AetherCodeHostValidationCode, message: string): AetherCodeHostValidationResult<never> {
  return { ok: false, error: { code, message } };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isSafeId(value: unknown): value is string {
  return typeof value === "string" && SAFE_ID.test(value);
}

function isNonEmptyString(value: unknown, maxBytes = 4096): value is string {
  return typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= maxBytes;
}

function isTimestamp(value: unknown): value is string {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0;
}

function isPositiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  label = "frame",
): AetherCodeHostValidationResult<Record<string, unknown>> {
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) return fail("UNKNOWN_FIELD", `${label} contains unknown field ${key}`);
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) return fail("INVALID_FRAME", `${label} is missing ${key}`);
  }
  return pass(value);
}

function findSecret(value: unknown, path = ""): string | null {
  if (typeof value === "string") {
    if (!ALLOWED_SENSITIVE_VALUES.has(path) && SENSITIVE_VALUE.test(value)) return path || "<root>";
    return null;
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      const found = findSecret(item, `${path}[${index}]`);
      if (found) return found;
    }
    return null;
  }
  if (!isRecord(value)) return null;
  for (const [key, item] of Object.entries(value)) {
    const itemPath = path ? `${path}.${key}` : key;
    if (SENSITIVE_KEY.test(key) && !ALLOWED_SENSITIVE_KEYS.has(itemPath)) return itemPath;
    const found = findSecret(item, itemPath);
    if (found) return found;
  }
  return null;
}

function validateFeatures(value: unknown): AetherCodeHostValidationResult<readonly string[]> {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    return fail("INVALID_FRAME", "features must be a string array");
  }
  const known = new Set<string>(AETHER_CODE_HOST_FEATURES);
  const unknown = value.find((item) => !known.has(String(item)));
  if (unknown !== undefined) return fail("UNKNOWN_FEATURE", `unknown feature ${String(unknown)}`);
  if (new Set(value).size !== value.length) return fail("INVALID_FRAME", "features must be unique");
  return pass(value as string[]);
}

function validateBuild(value: unknown): AetherCodeHostValidationResult<Record<string, unknown>> {
  if (!isRecord(value)) return fail("INVALID_FRAME", "hello.build must be an object");
  const shape = exactKeys(value, [
    "agent_git_sha",
    "agent_version",
    "executable_sha256",
    "publisher",
    "host_protocol",
    "exec_protocol",
  ], [], "hello.build");
  if (!shape.ok) return shape;
  if (typeof value["agent_git_sha"] !== "string" || !SHA1.test(value["agent_git_sha"])) {
    return fail("INVALID_FRAME", "hello.build.agent_git_sha must be lowercase 40-hex");
  }
  if (!isNonEmptyString(value["agent_version"], 64)) return fail("INVALID_FRAME", "invalid agent version");
  if (typeof value["executable_sha256"] !== "string" || !SHA256.test(value["executable_sha256"])) {
    return fail("INVALID_FRAME", "hello.build.executable_sha256 must be lowercase 64-hex");
  }
  if (!isNonEmptyString(value["publisher"], 256)) return fail("INVALID_FRAME", "invalid publisher");
  if (value["host_protocol"] !== AETHER_CODE_HOST_PROTOCOL) {
    return fail("UNSUPPORTED_HOST_PROTOCOL", "worker build declares an unsupported host protocol");
  }
  if (value["exec_protocol"] !== AETHER_CODE_EXEC_PROTOCOL) {
    return fail("UNSUPPORTED_EXEC_PROTOCOL", "worker build declares an unsupported exec protocol");
  }
  return pass(value);
}

function validateHello(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "worker_nonce",
    "pid",
    "pid_started_at",
    "build",
    "supported_exec_protocols",
    "supported_features",
  ], [], "hello");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["worker_nonce"])) return fail("INVALID_FRAME", "invalid worker_nonce");
  if (!isPositiveInteger(frame["pid"])) return fail("INVALID_FRAME", "invalid worker pid");
  if (!isTimestamp(frame["pid_started_at"])) return fail("INVALID_FRAME", "invalid pid_started_at");
  const build = validateBuild(frame["build"]);
  if (!build.ok) return build;
  const protocols = frame["supported_exec_protocols"];
  if (!Array.isArray(protocols) || protocols.length !== 1 || protocols[0] !== AETHER_CODE_EXEC_PROTOCOL) {
    return fail("UNSUPPORTED_EXEC_PROTOCOL", "worker must support exactly aether.exec/2");
  }
  const features = validateFeatures(frame["supported_features"]);
  if (!features.ok) return features;
  return pass(frame);
}

function validateAttempt(value: unknown): AetherCodeHostValidationResult<Record<string, unknown>> {
  if (!isRecord(value)) return fail("INVALID_FRAME", "start.attempt must be an object");
  const shape = exactKeys(value, [
    "project_id",
    "lane_id",
    "session_id",
    "attempt_id",
    "generation",
    "base_sha",
    "worktree_id",
    "settings_revision",
    "permission_profile",
    "model",
    "max_uvt",
    "authority_expires_at",
    "lease_epoch",
    "idempotency_key",
  ], [], "start.attempt");
  if (!shape.ok) return shape;
  for (const key of ["project_id", "lane_id", "session_id", "attempt_id", "worktree_id", "settings_revision", "idempotency_key"]) {
    if (!isSafeId(value[key])) return fail("INVALID_FRAME", `invalid start.attempt.${key}`);
  }
  if (!isNonEmptyString(value["permission_profile"], 128)) return fail("INVALID_FRAME", "invalid permission_profile");
  if (!isNonEmptyString(value["model"], 256)) return fail("INVALID_FRAME", "invalid model");
  if (!isPositiveInteger(value["generation"])) return fail("INVALID_FRAME", "invalid generation");
  if (typeof value["base_sha"] !== "string" || !SHA1.test(value["base_sha"])) return fail("INVALID_FRAME", "invalid base_sha");
  if (!isPositiveInteger(value["max_uvt"])) return fail("INVALID_FRAME", "invalid max_uvt");
  if (!isTimestamp(value["authority_expires_at"])) return fail("INVALID_FRAME", "invalid authority_expires_at");
  if (!isPositiveInteger(value["lease_epoch"])) return fail("INVALID_FRAME", "invalid lease_epoch");
  return pass(value);
}

function validateStart(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "worker_nonce",
    "main_nonce",
    "attempt",
    "request",
    "settings",
    "workspace",
    "lease",
    "budget",
    "credential",
    "cursors",
    "exec_protocol",
    "required_features",
  ], [], "start");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["worker_nonce"]) || !isSafeId(frame["main_nonce"])) {
    return fail("INVALID_FRAME", "start nonces are invalid");
  }
  if (frame["exec_protocol"] !== AETHER_CODE_EXEC_PROTOCOL) {
    return fail("UNSUPPORTED_EXEC_PROTOCOL", "start requires an unsupported exec protocol");
  }
  const features = validateFeatures(frame["required_features"]);
  if (!features.ok) return features;
  const attempt = validateAttempt(frame["attempt"]);
  if (!attempt.ok) return attempt;

  const request = frame["request"];
  if (!isRecord(request)) return fail("INVALID_FRAME", "start.request must be an object");
  const requestShape = exactKeys(request, ["task"], [], "start.request");
  if (!requestShape.ok) return requestShape;
  if (!isNonEmptyString(request["task"], 16 * 1024)) return fail("INVALID_FRAME", "start.request.task is invalid");

  const settings = frame["settings"];
  if (!isRecord(settings)) return fail("INVALID_FRAME", "start.settings must be an object");
  const settingsShape = exactKeys(settings, ["revision", "values"], [], "start.settings");
  if (!settingsShape.ok) return settingsShape;
  if (!isSafeId(settings["revision"]) || !isRecord(settings["values"])) return fail("INVALID_FRAME", "start.settings is invalid");

  const workspace = frame["workspace"];
  if (!isRecord(workspace)) return fail("INVALID_FRAME", "start.workspace must be an object");
  const workspaceShape = exactKeys(workspace, ["canonical_root", "repository_id", "worktree_id", "base_sha"], [], "start.workspace");
  if (!workspaceShape.ok) return workspaceShape;
  if (!isNonEmptyString(workspace["canonical_root"], 4096) || !isSafeId(workspace["repository_id"]) || !isSafeId(workspace["worktree_id"])) {
    return fail("INVALID_FRAME", "start.workspace identity is invalid");
  }
  if (typeof workspace["base_sha"] !== "string" || !SHA1.test(workspace["base_sha"])) return fail("INVALID_FRAME", "start.workspace.base_sha is invalid");

  const lease = frame["lease"];
  if (!isRecord(lease)) return fail("INVALID_FRAME", "start.lease must be an object");
  const leaseShape = exactKeys(lease, ["epoch", "fence_token", "fence_token_digest"], [], "start.lease");
  if (!leaseShape.ok) return leaseShape;
  if (!isPositiveInteger(lease["epoch"]) || !isNonEmptyString(lease["fence_token"], 4096)) return fail("INVALID_FRAME", "start.lease is invalid");
  if (typeof lease["fence_token_digest"] !== "string" || !SHA256_TAGGED.test(lease["fence_token_digest"])) {
    return fail("INVALID_FRAME", "start.lease.fence_token_digest is invalid");
  }

  const budget = frame["budget"];
  if (!isRecord(budget)) return fail("INVALID_FRAME", "start.budget must be an object");
  const budgetShape = exactKeys(budget, ["max_uvt", "deadline_at", "max_controls", "max_steers", "max_steer_bytes"], [], "start.budget");
  if (!budgetShape.ok) return budgetShape;
  if (!isPositiveInteger(budget["max_uvt"]) || !isTimestamp(budget["deadline_at"])) return fail("INVALID_FRAME", "start.budget is invalid");
  for (const key of ["max_controls", "max_steers", "max_steer_bytes"]) {
    if (!isPositiveInteger(budget[key])) return fail("INVALID_FRAME", `start.budget.${key} is invalid`);
  }

  const credential = frame["credential"];
  if (!isRecord(credential)) return fail("INVALID_FRAME", "start.credential must be an object");
  const credentialShape = exactKeys(credential, ["kind", "audience", "value", "expires_at", "single_use"], [], "start.credential");
  if (!credentialShape.ok) return credentialShape;
  if (credential["kind"] !== "attempt_capability") {
    return fail("FULL_SESSION_TOKEN_FORBIDDEN", "start accepts only an attempt-scoped capability");
  }
  if (credential["audience"] !== "aether-code-worker" || credential["single_use"] !== true) {
    return fail("INVALID_FRAME", "start.credential binding is invalid");
  }
  if (!isNonEmptyString(credential["value"], 8192) || !isTimestamp(credential["expires_at"])) {
    return fail("INVALID_FRAME", "start.credential value or expiry is invalid");
  }

  const cursors = frame["cursors"];
  if (!isRecord(cursors)) return fail("INVALID_FRAME", "start.cursors must be an object");
  const cursorShape = exactKeys(cursors, ["exec_sequence", "control_sequence"], [], "start.cursors");
  if (!cursorShape.ok) return cursorShape;
  if (!isNonNegativeInteger(cursors["exec_sequence"]) || !isNonNegativeInteger(cursors["control_sequence"])) {
    return fail("INVALID_FRAME", "start.cursors is invalid");
  }

  if (settings["revision"] !== attempt.value["settings_revision"]
      || workspace["worktree_id"] !== attempt.value["worktree_id"]
      || workspace["base_sha"] !== attempt.value["base_sha"]
      || lease["epoch"] !== attempt.value["lease_epoch"]
      || budget["max_uvt"] !== attempt.value["max_uvt"]
      || credential["expires_at"] !== attempt.value["authority_expires_at"]) {
    return fail("INVALID_FRAME", "start envelope contains inconsistent immutable bindings");
  }
  return pass(frame);
}

function validateReady(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "attempt_id",
    "ready_digest",
    "exec_protocol",
    "enabled_features",
  ], [], "ready");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["attempt_id"])) return fail("INVALID_FRAME", "invalid ready.attempt_id");
  if (typeof frame["ready_digest"] !== "string" || !SHA256_TAGGED.test(frame["ready_digest"])) return fail("INVALID_FRAME", "invalid ready digest");
  if (frame["exec_protocol"] !== AETHER_CODE_EXEC_PROTOCOL) return fail("UNSUPPORTED_EXEC_PROTOCOL", "ready selected an unsupported exec protocol");
  const features = validateFeatures(frame["enabled_features"]);
  return features.ok ? pass(frame) : features;
}

function validateHeartbeat(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "attempt_id",
    "lease_epoch",
    "worker_state",
    "last_exec_sequence",
    "sent_at",
  ], [], "heartbeat");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["attempt_id"]) || !isPositiveInteger(frame["lease_epoch"]) || !isNonNegativeInteger(frame["last_exec_sequence"])) {
    return fail("INVALID_FRAME", "heartbeat identity or sequence is invalid");
  }
  if (!["initializing", "running", "paused", "draining", "finalizing"].includes(String(frame["worker_state"]))) {
    return fail("INVALID_FRAME", "heartbeat worker_state is invalid");
  }
  if (!isTimestamp(frame["sent_at"])) return fail("INVALID_FRAME", "heartbeat sent_at is invalid");
  return pass(frame);
}

function validateSupervisorLease(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, ["protocol", "sequence", "type", "attempt_id", "lease_epoch", "renewal_id", "expires_at"], [], "supervisor_lease");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["attempt_id"]) || !isPositiveInteger(frame["lease_epoch"]) || !isSafeId(frame["renewal_id"]) || !isTimestamp(frame["expires_at"])) {
    return fail("INVALID_FRAME", "supervisor_lease is invalid");
  }
  return pass(frame);
}

function validateActionPayload(operation: string, value: unknown): AetherCodeHostValidationResult<Record<string, unknown>> {
  if (!isRecord(value)) return fail("INVALID_FRAME", "host action payload must be an object");
  const definitions: Record<string, { required: string[]; optional?: string[] }> = {
    repository_search: { required: ["query", "max_results"] },
    file_read: { required: ["path", "max_bytes"] },
    file_write: { required: ["path", "content", "expected_sha256"] },
    worktree_status: { required: [] },
    ci_command: { required: ["check_id"] },
    user_command: { required: ["approval_id"] },
    publish_artifact: { required: ["artifact_ref", "sha256", "bytes", "kind"] },
  };
  const definition = definitions[operation];
  if (!definition) return fail("INVALID_FRAME", `unsupported host action operation ${operation}`);
  const shape = exactKeys(value, definition.required, definition.optional ?? [], `host action ${operation} payload`);
  if (!shape.ok) return shape;
  if (operation === "repository_search" && (!isNonEmptyString(value["query"], 4096) || !isPositiveInteger(value["max_results"]))) {
    return fail("INVALID_FRAME", "repository_search payload is invalid");
  }
  if (operation === "file_read" && (!isNonEmptyString(value["path"], 4096) || !isPositiveInteger(value["max_bytes"]))) {
    return fail("INVALID_FRAME", "file_read payload is invalid");
  }
  if (operation === "file_write") {
    if (!isNonEmptyString(value["path"], 4096) || typeof value["content"] !== "string") return fail("INVALID_FRAME", "file_write payload is invalid");
    if (value["expected_sha256"] !== null && (typeof value["expected_sha256"] !== "string" || !SHA256_TAGGED.test(value["expected_sha256"]))) {
      return fail("INVALID_FRAME", "file_write expected_sha256 is invalid");
    }
  }
  if (operation === "ci_command" && !isSafeId(value["check_id"])) return fail("INVALID_FRAME", "ci_command check_id is invalid");
  if (operation === "user_command" && !isSafeId(value["approval_id"])) return fail("INVALID_FRAME", "user_command approval_id is invalid");
  if (operation === "publish_artifact") {
    if (!isNonEmptyString(value["artifact_ref"], 4096) || typeof value["sha256"] !== "string" || !SHA256_TAGGED.test(value["sha256"]) || !isNonNegativeInteger(value["bytes"]) || !isSafeId(value["kind"])) {
      return fail("INVALID_FRAME", "publish_artifact payload is invalid");
    }
  }
  return pass(value);
}

function validateHostActionRequest(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "attempt_id",
    "lease_epoch",
    "action_id",
    "idempotency_key",
    "operation",
    "payload",
  ], [], "host_action_request");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["attempt_id"]) || !isPositiveInteger(frame["lease_epoch"]) || !isSafeId(frame["action_id"]) || !isSafeId(frame["idempotency_key"])) {
    return fail("INVALID_FRAME", "host action identity is invalid");
  }
  if (typeof frame["operation"] !== "string" || !ACTIONS.has(frame["operation"])) return fail("INVALID_FRAME", "host action operation is invalid");
  const payload = validateActionPayload(frame["operation"], frame["payload"]);
  return payload.ok ? pass(frame) : payload;
}

function validatePermit(value: unknown): AetherCodeHostValidationResult<Record<string, unknown>> {
  if (!isRecord(value)) return fail("INVALID_FRAME", "host action permit must be an object");
  const shape = exactKeys(value, [
    "attempt_id",
    "action_id",
    "lease_epoch",
    "fence_token_digest",
    "executable_path",
    "executable_file_id",
    "executable_sha256",
    "argv",
    "cwd",
    "environment",
    "network_class",
    "timeout_ms",
    "output_cap_bytes",
    "expires_at",
    "single_use_nonce",
  ], [], "host action permit");
  if (!shape.ok) return shape;
  if (!isSafeId(value["attempt_id"]) || !isSafeId(value["action_id"]) || !isPositiveInteger(value["lease_epoch"])) return fail("INVALID_FRAME", "permit identity is invalid");
  if (typeof value["fence_token_digest"] !== "string" || !SHA256_TAGGED.test(value["fence_token_digest"])) return fail("INVALID_FRAME", "permit fence digest is invalid");
  if (!isNonEmptyString(value["executable_path"], 4096) || !isNonEmptyString(value["executable_file_id"], 512)) return fail("INVALID_FRAME", "permit executable identity is invalid");
  if (typeof value["executable_sha256"] !== "string" || !SHA256.test(value["executable_sha256"])) return fail("INVALID_FRAME", "permit executable digest is invalid");
  if (!Array.isArray(value["argv"]) || !value["argv"].every((item) => typeof item === "string" && Buffer.byteLength(item, "utf8") <= 4096)) return fail("INVALID_FRAME", "permit argv is invalid");
  if (!isNonEmptyString(value["cwd"], 4096) || !isRecord(value["environment"])) return fail("INVALID_FRAME", "permit cwd or environment is invalid");
  if (!Object.values(value["environment"]).every((item) => typeof item === "string" && Buffer.byteLength(item, "utf8") <= 4096)) return fail("INVALID_FRAME", "permit environment is invalid");
  if (!["denied", "sandboxed", "explicit_user_authorized"].includes(String(value["network_class"]))) return fail("INVALID_FRAME", "permit network_class is invalid");
  if (!isPositiveInteger(value["timeout_ms"]) || !isPositiveInteger(value["output_cap_bytes"]) || !isTimestamp(value["expires_at"]) || !isSafeId(value["single_use_nonce"])) {
    return fail("INVALID_FRAME", "permit bounds or expiry are invalid");
  }
  return pass(value);
}

function validateHostActionResponse(frame: Record<string, unknown>): AetherCodeHostValidationResult<Record<string, unknown>> {
  const shape = exactKeys(frame, [
    "protocol",
    "sequence",
    "type",
    "attempt_id",
    "lease_epoch",
    "action_id",
    "idempotency_key",
    "status",
  ], ["result", "permit", "error"], "host_action_response");
  if (!shape.ok) return shape;
  if (!isSafeId(frame["attempt_id"]) || !isPositiveInteger(frame["lease_epoch"]) || !isSafeId(frame["action_id"]) || !isSafeId(frame["idempotency_key"])) {
    return fail("INVALID_FRAME", "host action response identity is invalid");
  }
  const status = frame["status"];
  if (status === "completed") {
    if (!isRecord(frame["result"]) || Object.hasOwn(frame, "permit") || Object.hasOwn(frame, "error")) return fail("INVALID_FRAME", "completed response must contain only result");
    const resultShape = exactKeys(frame["result"], ["receipt_id", "payload"], [], "host action result");
    if (!resultShape.ok) return resultShape;
    if (!isSafeId(frame["result"]["receipt_id"]) || !isRecord(frame["result"]["payload"])) return fail("INVALID_FRAME", "host action result is invalid");
    return pass(frame);
  }
  if (status === "permitted") {
    if (Object.hasOwn(frame, "result") || Object.hasOwn(frame, "error")) return fail("INVALID_FRAME", "permitted response must contain only permit");
    const permit = validatePermit(frame["permit"]);
    return permit.ok ? pass(frame) : permit;
  }
  if (status === "refused" || status === "error") {
    if (!isRecord(frame["error"]) || Object.hasOwn(frame, "result") || Object.hasOwn(frame, "permit")) return fail("INVALID_FRAME", `${status} response must contain only error`);
    const errorShape = exactKeys(frame["error"], ["code", "message", "retryable"], [], "host action error");
    if (!errorShape.ok) return errorShape;
    if (!isSafeId(frame["error"]["code"]) || !isNonEmptyString(frame["error"]["message"], 4096) || typeof frame["error"]["retryable"] !== "boolean") {
      return fail("INVALID_FRAME", "host action error is invalid");
    }
    return pass(frame);
  }
  return fail("INVALID_FRAME", "host action response status is invalid");
}

/**
 * Validate one private host-channel frame. This function freezes wire shape;
 * it does not launch a worker, own a lifecycle, or authorize an action.
 */
export function validateAetherCodeHostFrame(
  line: string,
  direction: AetherCodeHostDirection,
): AetherCodeHostValidationResult<Record<string, unknown>> {
  if (Buffer.byteLength(line, "utf8") > AETHER_CODE_HOST_MAX_FRAME_BYTES) {
    return fail("FRAME_TOO_LARGE", `host frame exceeds ${AETHER_CODE_HOST_MAX_FRAME_BYTES} bytes`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return fail("MALFORMED_JSON", "host frame is not valid JSON");
  }
  if (!isRecord(parsed)) return fail("INVALID_FRAME", "host frame must be an object");
  if (parsed["protocol"] !== AETHER_CODE_HOST_PROTOCOL) return fail("UNSUPPORTED_HOST_PROTOCOL", "unsupported host protocol");
  if (!isNonNegativeInteger(parsed["sequence"])) return fail("INVALID_FRAME", "host frame sequence must be a non-negative integer");
  if (typeof parsed["type"] !== "string" || !HOST_TYPES.has(parsed["type"] as AetherCodeHostMessageType)) return fail("INVALID_FRAME", "unsupported host frame type");
  const type = parsed["type"] as AetherCodeHostMessageType;
  if ((direction === "worker_to_host" && !WORKER_TYPES.has(type)) || (direction === "host_to_worker" && !MAIN_TYPES.has(type))) {
    return fail("WRONG_DIRECTION", `${type} is not legal in ${direction}`);
  }
  const secretPath = findSecret(parsed);
  if (secretPath) return fail("SECRET_EXPOSURE", `secret-bearing data is forbidden at ${secretPath}`);
  switch (type) {
    case "hello": return validateHello(parsed);
    case "start": return validateStart(parsed);
    case "ready": return validateReady(parsed);
    case "heartbeat": return validateHeartbeat(parsed);
    case "supervisor_lease": return validateSupervisorLease(parsed);
    case "host_action_request": return validateHostActionRequest(parsed);
    case "host_action_response": return validateHostActionResponse(parsed);
  }
}

/** Cloud-specific control gate; the underlying aether.exec.control/2 parser is unchanged. */
export function validateAetherCodeControlLine(line: string): AetherCodeHostValidationResult<ControlFrame> {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return fail("MALFORMED_JSON", "control frame is not valid JSON");
  }
  const secretPath = findSecret(raw);
  if (secretPath) return fail("SECRET_EXPOSURE", `secret-bearing data is forbidden at ${secretPath}`);
  const parsed = parseControlFrame(line, HEADLESS_CONTROL_PROTOCOL_V2);
  return parsed.ok ? pass(parsed.frame) : fail("INVALID_FRAME", parsed.error);
}

export function validateAetherCodeDiagnosticLine(line: string): AetherCodeHostValidationResult<string> {
  if (Buffer.byteLength(line, "utf8") > AETHER_CODE_HOST_MAX_FRAME_BYTES) {
    return fail("FRAME_TOO_LARGE", `diagnostic line exceeds ${AETHER_CODE_HOST_MAX_FRAME_BYTES} bytes`);
  }
  if (SENSITIVE_VALUE.test(line)) return fail("SECRET_EXPOSURE", "secret-bearing diagnostic is forbidden");
  return pass(line);
}

export function aetherCodeReadyDigest(input: AetherCodeReadyDigestInput): string {
  const payload = { protocol: AETHER_CODE_HOST_PROTOCOL, ...input };
  return `sha256:${createHash("sha256").update(canonicalJson(payload), "utf8").digest("hex")}`;
}
