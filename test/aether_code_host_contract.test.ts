import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import {
  AETHER_CODE_CONTROL_PROTOCOL,
  AETHER_CODE_EXEC_PROTOCOL,
  AETHER_CODE_HOST_FEATURES,
  AETHER_CODE_HOST_PROTOCOL,
  aetherCodeReadyDigest,
  validateAetherCodeControlLine,
  validateAetherCodeDiagnosticLine,
  validateAetherCodeHostFrame,
  type AetherCodeHostDirection,
  type AetherCodeHostValidationCode,
} from "../src/core/aether_code_host_protocol.js";
import {
  HEADLESS_CONTROL_PROTOCOL_V2,
  HEADLESS_PROTOCOL_V2,
  V2ControlLedger,
  validateHeadlessFrames,
  type V2ControlOutcome,
} from "../src/core/headless_protocol.js";

const FIXTURE_ROOT = resolve(process.cwd(), "contracts", "aether-code", "host-v1");
const FIXTURE_FILES = [
  "completion-ordering.json",
  "controls.jsonl",
  "handshake.jsonl",
  "host-actions.jsonl",
  "secret-boundary.jsonl",
] as const;

interface VectorExpectation {
  ok: boolean;
  code?: AetherCodeHostValidationCode | "OUT_OF_ORDER" | "PROCESS_EXIT_BEFORE_READY" | "HANDSHAKE_TIMEOUT" | "STALE_LEASE";
  outcome?: string | V2ControlOutcome;
  decision?: "new" | "duplicate" | "rejected";
  error?: string;
  complete?: V2ControlOutcome;
}

interface TestVector {
  schema: "aether.code.test-vector/1";
  id: string;
  scenario: string;
  step: number;
  at_ms?: number;
  channel: "host_ipc" | "exec_stdin" | "stderr" | "process" | "clock";
  direction: AetherCodeHostDirection;
  expect: VectorExpectation;
  wire?: unknown;
  event?: Record<string, unknown>;
}

interface FixtureManifest {
  schema: "aether.code.fixture-manifest/1";
  protocol: string;
  exec_protocol: string;
  control_protocol: string;
  digest_algorithm: string;
  files: Array<{ path: string; bytes: number; sha256: string; cases: number }>;
  bundle_sha256: string;
}

interface CompletionEvent {
  kind: string;
  wire?: Record<string, unknown>;
  exit_code?: number;
}

interface CompletionScenario {
  id: string;
  events: CompletionEvent[];
  expected: { state: "FINALIZING" | "TERMINAL"; outcome?: string };
}

interface CompletionFixture {
  schema: "aether.code.completion-vectors/1";
  scenarios: CompletionScenario[];
}

function rawFixture(path: string): string {
  return readFileSync(resolve(FIXTURE_ROOT, path), "utf8");
}

function jsonFixture<T>(path: string): T {
  return JSON.parse(rawFixture(path)) as T;
}

function jsonlFixture(path: string): TestVector[] {
  return rawFixture(path)
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as TestVector);
}

function wireLine(vector: TestVector): string {
  assert.notEqual(vector.wire, undefined, `${vector.id} must contain wire data`);
  return typeof vector.wire === "string" ? vector.wire : JSON.stringify(vector.wire);
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  assert.ok(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value as Record<string, unknown>;
}

function sha256(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

function bundleDigest(files: readonly { path: string; sha256: string }[]): string {
  const material = [...files]
    .sort((a, b) => a.path.localeCompare(b.path))
    .map((file) => `${file.path}\0${file.sha256}\n`)
    .join("");
  return sha256(material);
}

test("host fixture manifest pins every canonical raw byte and one bundle digest", () => {
  const manifest = jsonFixture<FixtureManifest>("manifest.json");
  assert.equal(manifest.schema, "aether.code.fixture-manifest/1");
  assert.equal(manifest.protocol, AETHER_CODE_HOST_PROTOCOL);
  assert.equal(manifest.exec_protocol, HEADLESS_PROTOCOL_V2);
  assert.equal(manifest.control_protocol, HEADLESS_CONTROL_PROTOCOL_V2);
  assert.equal(manifest.digest_algorithm, "sha256(sorted(path + NUL + raw_file_sha256 + LF))");
  assert.deepEqual(manifest.files.map((file) => file.path), [...FIXTURE_FILES]);
  for (const file of manifest.files) {
    const raw = rawFixture(file.path);
    assert.equal(Buffer.byteLength(raw, "utf8"), file.bytes, `${file.path} byte count drift`);
    assert.equal(sha256(raw), file.sha256, `${file.path} digest drift`);
    const cases = file.path.endsWith(".jsonl")
      ? raw.split(/\r?\n/).filter(Boolean).length
      : jsonFixture<CompletionFixture>(file.path).scenarios.length;
    assert.equal(cases, file.cases, `${file.path} case count drift`);
  }
  assert.equal(bundleDigest(manifest.files), manifest.bundle_sha256);
});

test("the private host contract selects, rather than changes, exec/control v2", () => {
  assert.equal(AETHER_CODE_EXEC_PROTOCOL, HEADLESS_PROTOCOL_V2);
  assert.equal(AETHER_CODE_CONTROL_PROTOCOL, HEADLESS_CONTROL_PROTOCOL_V2);
  assert.equal(AETHER_CODE_HOST_PROTOCOL, "aether.code.host/1");
  assert.deepEqual(AETHER_CODE_HOST_FEATURES, ["host_actions_v1", "supervisor_lease_v1"]);
  const source = readFileSync(resolve(process.cwd(), "src", "core", "headless_protocol.ts"), "utf8");
  assert.match(source, /HEADLESS_PROTOCOL_V2 = "aether\.exec\/2"/);
  assert.match(source, /HEADLESS_CONTROL_PROTOCOL_V2 = "aether\.exec\.control\/2"/);
});

test("hello/start/ready fixtures form one bound, sequenced handshake", () => {
  const vectors = jsonlFixture("handshake.jsonl").filter((vector) => vector.scenario === "valid-handshake");
  assert.deepEqual(vectors.map((vector) => vector.id), ["valid-hello", "valid-start", "valid-ready"]);
  const next = { worker_to_host: 0, host_to_worker: 0 };
  for (const vector of vectors) {
    assert.equal(vector.schema, "aether.code.test-vector/1");
    const result = validateAetherCodeHostFrame(wireLine(vector), vector.direction);
    assert.equal(result.ok, true, vector.id);
    assert.ok(result.ok);
    assert.equal(result.value["sequence"], next[vector.direction], vector.id);
    next[vector.direction] += 1;
  }

  const hello = asRecord(vectors[0]?.wire, "hello");
  const start = asRecord(vectors[1]?.wire, "start");
  const ready = asRecord(vectors[2]?.wire, "ready");
  const attempt = asRecord(start["attempt"], "start.attempt");
  assert.equal(start["worker_nonce"], hello["worker_nonce"]);
  assert.equal(ready["attempt_id"], attempt["attempt_id"]);
  const supported = new Set(asRecord(hello, "hello")["supported_features"] as string[]);
  for (const feature of start["required_features"] as string[]) assert.ok(supported.has(feature));
  assert.deepEqual(ready["enabled_features"], start["required_features"]);
  assert.equal(ready["ready_digest"], aetherCodeReadyDigest({
    worker_nonce: String(hello["worker_nonce"]),
    main_nonce: String(start["main_nonce"]),
    project_id: String(attempt["project_id"]),
    lane_id: String(attempt["lane_id"]),
    session_id: String(attempt["session_id"]),
    attempt_id: String(attempt["attempt_id"]),
    generation: Number(attempt["generation"]),
    lease_epoch: Number(attempt["lease_epoch"]),
  }));
});

test("handshake vectors fail closed on malformed, skewed, unknown, out-of-order, crash, and hang cases", () => {
  const vectors = jsonlFixture("handshake.jsonl").filter((vector) => vector.scenario !== "valid-handshake");
  for (const vector of vectors) {
    assert.equal(vector.expect.ok, false, vector.id);
    assert.equal(vector.expect.outcome, "LOST", vector.id);
    if (vector.channel === "host_ipc") {
      const result = validateAetherCodeHostFrame(wireLine(vector), vector.direction);
      if (vector.expect.code === "OUT_OF_ORDER") {
        assert.equal(result.ok, true, `${vector.id} is structurally valid before state validation`);
        const wire = asRecord(vector.wire, vector.id);
        assert.equal(wire["type"], "ready");
        assert.equal(vector.step, 1);
      } else {
        assert.equal(result.ok, false, vector.id);
        assert.ok(!result.ok);
        assert.equal(result.error.code, vector.expect.code, vector.id);
      }
      continue;
    }
    if (vector.channel === "process") {
      assert.equal(vector.event?.["kind"], "process_exit");
      assert.equal(vector.expect.code, "PROCESS_EXIT_BEFORE_READY");
      continue;
    }
    assert.equal(vector.channel, "clock");
    assert.equal(vector.event?.["kind"], "deadline");
    assert.ok(Number(vector.at_ms) > Number(vector.event?.["deadline_ms"]));
    assert.equal(vector.expect.code, "HANDSHAKE_TIMEOUT");
  }
});

test("control vectors preserve the existing v2 parser and idempotent ledger semantics", () => {
  const ledger = new V2ControlLedger();
  const vectors = jsonlFixture("controls.jsonl");
  for (const vector of vectors.filter((item) => item.scenario === "control-ledger")) {
    const parsed = validateAetherCodeControlLine(wireLine(vector));
    assert.equal(parsed.ok, true, vector.id);
    assert.ok(parsed.ok);
    const decision = ledger.begin(parsed.value);
    assert.equal(decision.kind, vector.expect.decision, vector.id);
    if (decision.kind === "rejected") {
      assert.equal(decision.error, vector.expect.error, vector.id);
    } else if (decision.kind === "duplicate") {
      assert.deepEqual(decision.outcome, vector.expect.outcome, vector.id);
    } else {
      assert.ok(vector.expect.complete, `${vector.id} must provide its deterministic completion`);
      ledger.complete(parsed.value, vector.expect.complete);
    }
  }
  assert.deepEqual(ledger.snapshot(), { nextSequence: 4, steerCount: 1, steerBytes: 45 });

  for (const vector of vectors.filter((item) => item.scenario !== "control-ledger")) {
    const parsed = validateAetherCodeControlLine(wireLine(vector));
    assert.equal(parsed.ok, false, vector.id);
    assert.ok(!parsed.ok);
    assert.equal(parsed.error.code, vector.expect.code, vector.id);
  }
});

test("host-action fixtures bind results and exact permits to attempt, action, idempotency, and epoch", () => {
  const vectors = jsonlFixture("host-actions.jsonl");
  const activeLeaseEpoch = 7;
  for (const vector of vectors) {
    const result = validateAetherCodeHostFrame(wireLine(vector), vector.direction);
    if (vector.expect.code === "STALE_LEASE") {
      assert.equal(result.ok, true, "stale leases are schema-valid before authority validation");
      assert.notEqual(asRecord(vector.wire, vector.id)["lease_epoch"], activeLeaseEpoch);
    } else {
      assert.equal(result.ok, vector.expect.ok, vector.id);
      if (!result.ok) assert.equal(result.error.code, vector.expect.code, vector.id);
    }
  }

  for (const scenario of ["host-executed-action", "exact-command-permit"] as const) {
    const [requestVector, responseVector] = vectors.filter((vector) => vector.scenario === scenario);
    assert.ok(requestVector?.wire && responseVector?.wire);
    const request = asRecord(requestVector.wire, `${scenario} request`);
    const response = asRecord(responseVector.wire, `${scenario} response`);
    for (const key of ["attempt_id", "lease_epoch", "action_id", "idempotency_key"] as const) {
      assert.equal(response[key], request[key], `${scenario} ${key} drift`);
    }
    if (response["status"] === "permitted") {
      const permit = asRecord(response["permit"], `${scenario} permit`);
      for (const key of ["attempt_id", "lease_epoch", "action_id"] as const) assert.equal(permit[key], request[key]);
      assert.deepEqual(permit["environment"], { CI: "1", NO_COLOR: "1" });
      assert.equal(permit["network_class"], "denied");
    }
  }
});

test("handshake and runtime vectors have gap-free independent directional sequences", () => {
  const vectors = [
    ...jsonlFixture("handshake.jsonl").filter((vector) => vector.scenario === "valid-handshake"),
    ...jsonlFixture("host-actions.jsonl"),
  ];
  const sequences = { worker_to_host: [] as number[], host_to_worker: [] as number[] };
  for (const vector of vectors) {
    if (vector.channel !== "host_ipc" || vector.expect.code === "INVALID_FRAME") continue;
    const wire = asRecord(vector.wire, vector.id);
    sequences[vector.direction].push(Number(wire["sequence"]));
  }
  assert.deepEqual(sequences.worker_to_host, [0, 1, 2, 3, 4, 5]);
  assert.deepEqual(sequences.host_to_worker, [0, 1, 2, 3]);
});

test("secret-boundary vectors allow only private start capability/fence paths", () => {
  const validStart = jsonlFixture("handshake.jsonl").find((vector) => vector.id === "valid-start");
  assert.ok(validStart);
  assert.equal(validateAetherCodeHostFrame(wireLine(validStart), validStart.direction).ok, true);

  const vectors = jsonlFixture("secret-boundary.jsonl");
  for (const vector of vectors) {
    const result = vector.channel === "stderr"
      ? validateAetherCodeDiagnosticLine(wireLine(vector))
      : validateAetherCodeHostFrame(wireLine(vector), vector.direction);
    assert.equal(result.ok, false, vector.id);
    assert.ok(!result.ok);
    assert.equal(result.error.code, vector.expect.code, vector.id);
  }
  const syntheticMarker = "sk-test-only-not-real-123456789";
  assert.ok(rawFixture("secret-boundary.jsonl").includes(syntheticMarker));
  assert.ok(rawFixture("controls.jsonl").includes(syntheticMarker));
  for (const file of ["handshake.jsonl", "host-actions.jsonl"] as const) {
    assert.ok(!rawFixture(file).includes(syntheticMarker), `${file} accepted vectors must not contain the negative marker`);
  }
});

function completionResult(events: readonly CompletionEvent[]): { state: "FINALIZING" | "TERMINAL"; outcome?: string } {
  const lines = events
    .filter((event) => event.kind === "exec_frame")
    .map((event) => JSON.stringify(event.wire));
  const terminalFrames = events.filter((event) => event.kind === "exec_frame" && event.wire?.["type"] === "terminal");
  const processExit = events.find((event) => event.kind === "process_exit");
  const stdoutEof = events.some((event) => event.kind === "stdout_eof");
  const containmentEmpty = events.some((event) => event.kind === "containment_empty");
  if (!processExit || !stdoutEof || !containmentEmpty) return { state: "FINALIZING" };
  const protocolErrors = validateHeadlessFrames(lines, HEADLESS_PROTOCOL_V2);
  if (protocolErrors.length > 0 || terminalFrames.length !== 1) return { state: "TERMINAL", outcome: "LOST" };
  if (processExit.exit_code !== 0) return { state: "TERMINAL", outcome: "FAILED" };
  const terminal = terminalFrames[0]?.wire;
  if (terminal?.["ok"] !== true || terminal["exit_code"] !== 0) return { state: "TERMINAL", outcome: "FAILED" };
  if (!events.some((event) => event.kind === "proof_valid")) return { state: "TERMINAL", outcome: "UNVERIFIED" };
  if (!events.some((event) => event.kind === "metering_reconciled") || !events.some((event) => event.kind === "lease_released")) {
    return { state: "FINALIZING" };
  }
  return { state: "TERMINAL", outcome: "SUCCEEDED" };
}

test("completion fixtures never infer success from process callback ordering or exit zero", () => {
  const fixture = jsonFixture<CompletionFixture>("completion-ordering.json");
  assert.equal(fixture.schema, "aether.code.completion-vectors/1");
  for (const scenario of fixture.scenarios) {
    assert.deepEqual(completionResult(scenario.events), scenario.expected, scenario.id);
  }
  const reversed = fixture.scenarios.find((scenario) => scenario.id === "exit-callback-before-buffered-terminal");
  assert.ok(reversed);
  assert.deepEqual(completionResult(reversed.events.slice(0, 1)), { state: "FINALIZING" });
});

test("canonical vector identifiers are unique across the bundle", () => {
  const vectors = ["controls.jsonl", "handshake.jsonl", "host-actions.jsonl", "secret-boundary.jsonl"]
    .flatMap((file) => jsonlFixture(file));
  const ids = vectors.map((vector) => vector.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const vector of vectors) {
    assert.equal(vector.schema, "aether.code.test-vector/1", vector.id);
    assert.ok(Number.isSafeInteger(vector.step) && vector.step > 0, vector.id);
  }
});
