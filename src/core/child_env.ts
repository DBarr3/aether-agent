// child_env.ts — what a child process is allowed to inherit.
//
// Four launchers in this repository spread `...process.env` into a child: the
// bundled brain, the local model child, the preview supervisor, and the device
// runtime. A parent holding AETHER_TOKEN, provider API keys, a device command
// key, or an MCP connector token hands every one of them to whatever it starts
// — a bundled model, a Python process, a dev server, a helper.
//
// None of those children needs a credential. The dev server needs PATH and a
// HOME; the model child needs PATH and PYTHONUTF8. They inherited secrets
// because `...process.env` is the shortest thing to type, not because anyone
// decided they should.
//
// THE DIRECTION OF THE DEFAULT IS THE WHOLE DESIGN
//
// This module denies by default and passes by exception. The alternative —
// copy everything, then delete the names that look sensitive — has the failure
// mode every denylist has: the newest secret is the one it does not know about.
// A launcher that starts denying and forgets to allow something shows up as a
// child that cannot find its PATH, loudly, in development. A launcher that
// starts copying and forgets to deny something shows up as a credential in a
// subprocess nobody audits.
//
// So `childEnv()` returns ONLY allowlisted names plus whatever the caller
// explicitly injects. `assertNoCredentials()` is the belt-and-braces check for
// tests and diagnostics — it reuses src/core/redaction.ts's SENSITIVE_KEY
// rather than inventing a second opinion about which names are credential-
// shaped.

import { SENSITIVE_KEY } from "./redaction.js";

/**
 * Names every child may see. Deliberately short and deliberately boring:
 * locale, paths, terminal shape, and the platform variables a process needs to
 * start at all on Windows.
 *
 * Nothing here identifies the user to a remote service. `USER`/`USERNAME` are
 * included because tools print them and some resolve a home directory from
 * them; they are not authentication.
 */
export const BASE_ALLOWLIST: readonly string[] = Object.freeze([
  // POSIX essentials
  "PATH", "HOME", "SHELL", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE",
  "TZ", "USER", "LOGNAME",
  // Terminal shape — omitting these makes child output unreadable, and none is
  // a secret.
  "TERM", "TERM_PROGRAM", "COLORTERM", "COLUMNS", "LINES", "NO_COLOR", "FORCE_COLOR",
  // Windows essentials. A Node child on Windows fails to spawn without
  // SYSTEMROOT and resolves nothing sensible without USERPROFILE.
  "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
  "USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
  "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
  "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS",
  // Network reachability. NO_PROXY carries no credential; the proxy URLs that
  // can are in OPTIONAL_ALLOWLIST and still face the userinfo check below.
  "NO_PROXY", "no_proxy",
]);

/**
 * Names a child may see only when the caller opts in. Kept separate from
 * BASE_ALLOWLIST so passing one is a visible decision at the call site.
 */
export const OPTIONAL_ALLOWLIST: readonly string[] = Object.freeze([
  "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
  "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "PYTHONUTF8", "PYTHONIOENCODING", "PYTHONHOME", "PYTHONPATH",
  "NODE_OPTIONS",
]);

/**
 * Every name a human has looked at and decided is not a credential.
 *
 * Exists so the name heuristic in `findCredentials` can be skipped for names
 * that were reviewed, without weakening it for names that were not.
 */
const REVIEWED_NAMES: ReadonlySet<string> = new Set([
  ...BASE_ALLOWLIST,
  ...OPTIONAL_ALLOWLIST,
]);

export interface ChildEnvOptions {
  /** Extra names to pass through from the parent, beyond BASE_ALLOWLIST. */
  allow?: readonly string[];
  /** Values to set explicitly. The ONLY way to give a child a value the parent
   *  did not already expose under an allowlisted name. */
  inject?: Readonly<Record<string, string>>;
  /** Source environment. Injectable so tests never mutate process.env. */
  source?: NodeJS.ProcessEnv;
}

/**
 * Build a child environment from a minimal allowlist.
 *
 * Undefined and empty values are dropped rather than passed through: an empty
 * PATH is worse than an absent one, because it looks configured.
 */
export function childEnv(options: ChildEnvOptions = {}): Record<string, string> {
  const source = options.source ?? process.env;
  const allowed = new Set<string>([...BASE_ALLOWLIST, ...(options.allow ?? [])]);
  const out: Record<string, string> = {};

  for (const name of allowed) {
    const value = source[name];
    if (typeof value === "string" && value !== "") out[name] = value;
  }
  for (const [name, value] of Object.entries(options.inject ?? {})) {
    if (typeof value === "string" && value !== "") out[name] = value;
  }
  return out;
}

export interface CredentialLeak {
  /** The variable name. The VALUE is never included, here or anywhere. */
  name: string;
  reason: "sensitive-name" | "userinfo-url";
}

/**
 * Report credential-shaped entries in a built child environment.
 *
 * Two detectors, both name- or shape-based, neither echoing a value:
 *
 *  - a name matching SENSITIVE_KEY (the repository's canonical detector), and
 *  - a URL carrying `user:password@`, which is how a proxy variable smuggles a
 *    credential past a name check that only looked at "HTTPS_PROXY".
 */
export function findCredentials(
  env: Readonly<Record<string, string>>,
): CredentialLeak[] {
  const leaks: CredentialLeak[] = [];
  for (const [name, value] of Object.entries(env)) {
    // The NAME check applies only to names nobody has reviewed. SENSITIVE_KEY
    // documents itself as deliberately over-matching, and it can afford to
    // because its other consumers only fire on 32+ char hex values. Here it
    // classifies bare names, where over-matching is not free: `PATH` contains
    // `pat` (the PAT-token pattern) and case-insensitively matches, so an
    // unqualified check flags the one variable every child needs most.
    //
    // Reviewing a name is what REVIEWED_NAMES means, so a reviewed name is
    // exempt from the name heuristic — and only from that. The value-shape
    // check below still runs on everything, which is what catches an
    // allowlisted HTTPS_PROXY smuggling `user:password@`.
    if (!REVIEWED_NAMES.has(name) && SENSITIVE_KEY.test(name)) {
      leaks.push({ name, reason: "sensitive-name" });
      continue;
    }
    if (/^[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i.test(value)) {
      leaks.push({ name, reason: "userinfo-url" });
    }
  }
  return leaks;
}

/**
 * Throw if a child environment carries anything credential-shaped.
 *
 * The message names variables, never values — an error that prints the secret
 * it is complaining about has published it to every log that catches the throw.
 */
export function assertNoCredentials(
  env: Readonly<Record<string, string>>,
  label: string,
): void {
  const leaks = findCredentials(env);
  if (leaks.length === 0) return;
  const rendered = leaks.map((leak) => `${leak.name} (${leak.reason})`).join(", ");
  throw new Error(`${label} child environment carries credentials: ${rendered}`);
}

export interface CustodyReport {
  /** Names withheld from children. Names only — never values. */
  withheld: string[];
  /** How many variables the child actually receives. */
  passed: number;
}

/**
 * Summarize what the firewall is holding back, for `aether doctor`.
 *
 * Reports names and a count. A diagnostic that printed values would be the
 * exact leak this module exists to prevent, in the one place a user is most
 * likely to paste the output into a bug report.
 */
export function custodyReport(source: NodeJS.ProcessEnv = process.env): CustodyReport {
  const child = childEnv({ source });
  const withheld: string[] = [];
  for (const [name, value] of Object.entries(source)) {
    if (!value) continue;
    if (name in child) continue;
    if (SENSITIVE_KEY.test(name)) withheld.push(name);
  }
  withheld.sort();
  return { withheld, passed: Object.keys(child).length };
}
