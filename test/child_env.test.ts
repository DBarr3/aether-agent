// The child-environment firewall.
//
// The load-bearing test is "no seeded credential reaches a child": it seeds
// every credential-shaped variable this agent plausibly holds into a synthetic
// parent environment and asserts a child receives none of them. That is the
// requirement stated as an executable fact rather than a policy.
//
// Nothing here reads or mutates the real process.env — every case passes an
// explicit `source`, so the suite is hermetic and cannot pass or fail because
// of what happens to be set on the machine running it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { SENSITIVE_KEY } from "../src/core/redaction.js";
import {
  BASE_ALLOWLIST,
  assertNoCredentials,
  childEnv,
  custodyReport,
  findCredentials,
} from "../src/core/child_env.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");

/** Every credential-shaped variable this agent plausibly holds. All synthetic. */
const SEEDED_CREDENTIALS: Record<string, string> = {
  AETHER_TOKEN: "aek_" + "a".repeat(32),
  AETHER_REFRESH_TOKEN: "aer_" + "b".repeat(32),
  AETHER_DEVICE_TOKEN: "dev_" + "c".repeat(32),
  AETHER_DEVICE_COMMAND_KEY: "d".repeat(64),
  OPENAI_API_KEY: "sk-" + "e".repeat(24),
  ANTHROPIC_API_KEY: "sk-ant-" + "f".repeat(20),
  OPENROUTER_API_KEY: "sk-or-v1-" + "g".repeat(20),
  GITHUB_TOKEN: "ghp_" + "h".repeat(22),
  MCP_AUTH_TOKEN: "i".repeat(40),
  AWS_SECRET_ACCESS_KEY: "j".repeat(40),
  DATABASE_PASSWORD: "hunter2hunter2",
  STRIPE_SECRET_KEY: "sk_live_" + "k".repeat(20),
  SOME_PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----",
};

const BENIGN: Record<string, string> = {
  PATH: "/usr/bin:/bin",
  HOME: "/home/dev",
  LANG: "en_US.UTF-8",
  TERM: "xterm-256color",
  SYSTEMROOT: "C:\\Windows",
  USERPROFILE: "C:\\Users\\dev",
};

function parentEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return { ...BENIGN, ...SEEDED_CREDENTIALS, ...extra };
}

// --- the load-bearing proof -------------------------------------------------

test("no seeded credential reaches a child", () => {
  const child = childEnv({ source: parentEnv() });
  for (const name of Object.keys(SEEDED_CREDENTIALS)) {
    assert.ok(!(name in child), `${name} leaked into the child environment`);
  }
});

test("no seeded credential VALUE reaches a child under any name", () => {
  // Catches a rename: a value surviving under a different key is still a leak,
  // and a name-only assertion would miss it.
  const child = childEnv({ source: parentEnv() });
  const values = new Set(Object.values(SEEDED_CREDENTIALS));
  for (const value of Object.values(child)) {
    assert.ok(!values.has(value), "a credential value survived under another name");
  }
});

test("the child still gets what it needs to run", () => {
  const child = childEnv({ source: parentEnv() });
  assert.equal(child["PATH"], "/usr/bin:/bin");
  assert.equal(child["HOME"], "/home/dev");
  assert.equal(child["SYSTEMROOT"], "C:\\Windows");
});

test("a clean allowlisted environment reports no leak", () => {
  const asEnv = Object.fromEntries(BASE_ALLOWLIST.map((name) => [name, "x"]));
  assert.deepEqual(findCredentials(asEnv), []);
});

test("PATH is not a credential, despite matching the shared name pattern", () => {
  // Regression. SENSITIVE_KEY includes `pat` (for PAT tokens) and is
  // case-insensitive, so it matches "PATH". That is fine for its other
  // consumers, which only fire on 32+ char hex values — but an unqualified
  // name check here flagged the one variable every child needs most, and the
  // first run of this suite caught it.
  assert.ok(SENSITIVE_KEY.test("PATH"), "the shared pattern really does match PATH");
  assert.deepEqual(findCredentials({ PATH: "/usr/bin:/bin" }), []);
});

test("review exempts a name from the heuristic, not from the value check", () => {
  // HTTPS_PROXY is reviewed, so its name is not suspicious. A userinfo URL in
  // its value still is.
  assert.deepEqual(findCredentials({ HTTPS_PROXY: "https://proxy.example.com" }), []);
  assert.equal(
    findCredentials({ HTTPS_PROXY: "https://u:p@proxy.example.com" })[0]?.reason,
    "userinfo-url",
  );
});

test("an unreviewed credential-shaped name is still flagged", () => {
  assert.equal(
    findCredentials({ SOME_OTHER_TOKEN: "x" })[0]?.reason,
    "sensitive-name",
  );
});

// --- deny by default --------------------------------------------------------

test("an unknown variable is withheld even when it looks harmless", () => {
  const child = childEnv({ source: parentEnv({ MY_NEW_SETTING: "value" }) });
  assert.ok(!("MY_NEW_SETTING" in child));
});

test("a brand-new credential name nobody anticipated is still withheld", () => {
  // The point of deny-by-default: this needs no pattern update to be safe.
  const child = childEnv({
    source: parentEnv({ FUTURE_PROVIDER_XYZ: "z".repeat(40) }),
  });
  assert.ok(!("FUTURE_PROVIDER_XYZ" in child));
});

test("opting a name in passes it through", () => {
  const child = childEnv({
    source: parentEnv({ PYTHONPATH: "/opt/lib" }),
    allow: ["PYTHONPATH"],
  });
  assert.equal(child["PYTHONPATH"], "/opt/lib");
});

test("injected values reach the child", () => {
  const child = childEnv({ source: parentEnv(), inject: { PYTHONUTF8: "1" } });
  assert.equal(child["PYTHONUTF8"], "1");
});

test("empty and undefined values are dropped, not passed as empty strings", () => {
  const child = childEnv({ source: { PATH: "", HOME: undefined, LANG: "C" } });
  assert.ok(!("PATH" in child));
  assert.ok(!("HOME" in child));
  assert.equal(child["LANG"], "C");
});

// --- credential detection ---------------------------------------------------

test("a sensitive name is reported without its value", () => {
  const leaks = findCredentials({ MY_API_KEY: "secret-value-here" });
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0]!.name, "MY_API_KEY");
  assert.equal(leaks[0]!.reason, "sensitive-name");
  assert.ok(!JSON.stringify(leaks).includes("secret-value-here"));
});

test("a proxy URL carrying userinfo is caught even though its NAME is benign", () => {
  const leaks = findCredentials({
    HTTPS_PROXY: "https://user:pw@proxy.example.com:8080",
  });
  assert.equal(leaks.length, 1);
  assert.equal(leaks[0]!.reason, "userinfo-url");
});

test("a proxy URL without credentials is fine", () => {
  assert.deepEqual(
    findCredentials({ HTTPS_PROXY: "https://proxy.example.com:8080" }),
    [],
  );
});

test("assertNoCredentials throws naming variables, never values", () => {
  assert.throws(
    () => assertNoCredentials({ AETHER_TOKEN: "aek_secret" }, "bundled brain"),
    (err: Error) => {
      assert.match(err.message, /bundled brain/);
      assert.match(err.message, /AETHER_TOKEN/);
      assert.ok(!err.message.includes("aek_secret"), "the value must not be echoed");
      return true;
    },
  );
});

test("a clean child environment passes the assertion", () => {
  assertNoCredentials(childEnv({ source: parentEnv() }), "any launcher");
});

// --- diagnostics ------------------------------------------------------------

test("custodyReport names what is withheld and never a value", () => {
  const report = custodyReport(parentEnv());
  assert.ok(report.withheld.includes("AETHER_TOKEN"));
  assert.ok(report.withheld.includes("OPENAI_API_KEY"));
  assert.ok(report.passed > 0);
  const serialized = JSON.stringify(report);
  for (const value of Object.values(SEEDED_CREDENTIALS)) {
    assert.ok(!serialized.includes(value), "custody report leaked a value");
  }
});

test("custodyReport is sorted so a diff is readable", () => {
  const { withheld } = custodyReport(parentEnv());
  assert.deepEqual(withheld, [...withheld].sort());
});

// --- the launchers actually use it ------------------------------------------

for (const relative of [
  "src/core/brain_bundled_child.ts",
  "src/core/brain_local.ts",
  "src/core/preview_supervisor.ts",
  "src/commands/device.ts",
]) {
  test(`${relative} no longer spreads process.env into a child`, () => {
    const source = readFileSync(join(repoRoot, relative), "utf8");
    assert.ok(
      !/env:\s*\{\s*\.\.\.process\.env/.test(source),
      `${relative} must build its child environment with childEnv()`,
    );
    assert.ok(source.includes("childEnv("), `${relative} must call childEnv()`);
  });
}
