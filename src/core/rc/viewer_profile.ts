// viewer_profile.ts — the Agent's half of the viewer-only contract.
//
// The Cloud side landed as lib/remote_session/viewer_profile.py (RC-01). This
// is the producer mirror: the host may only emit what a viewer build is allowed
// to receive, and it must be impossible to grow a control surface here without
// a test going red.
//
// WHY A MIRROR AND NOT A RESTATEMENT
//
// Two independently maintained copies of one allowlist drift, and the drift is
// silent until someone notices a viewer rendering an event class the host was
// never supposed to send. So the shape here is deliberately narrow — a frozen
// list and two predicates — and test/rc_viewer_profile.test.ts pins it against
// the Cloud manifest's contents. A divergence fails the build.
//
// WHY `transcript` IS ABSENT
//
// The frozen `aether.remote_session.v1` vocabulary includes it, and PR #108
// emitted it. v1 is a structured-event view: raw prompts and model transcripts
// are out, and bounded summaries need a per-session exposure choice that does
// not exist yet. Shipping the type before that choice exists would make "can a
// viewer read my prompts?" depend on which producer happened to be wired, which
// is not an answer anyone can rely on.

/** Every capability a viewer release exposes. Exactly one. */
export const VIEWER_CAPABILITIES = ["observe"] as const;

/** The grant purpose a viewer session may hold. `control` belongs to a train
 *  that is deferred, not cancelled — this lane simply never asks for it. */
export const VIEWER_GRANT_PURPOSE = "observe" as const;

/** Presence roles a viewer client may occupy. `controller` is absent. */
export const VIEWER_PRESENCE_ROLES = ["host", "observer"] as const;

/**
 * Event classes the host may publish.
 *
 * A strict subset of the frozen v1 vocabulary: `transcript` is excluded (see
 * the header), and `session`/`presence` are kept because a viewer that cannot
 * tell whether the host is alive is not observing anything.
 */
export const VIEWER_EVENT_TYPES = [
  "session",
  "presence",
  "plan",
  "subagent",
  "tool_activity",
  "diff_summary",
  "tests",
  "ci",
  "pr_status",
  "artifact",
  "preview",
  "done",
  "error",
] as const;

export type ViewerEventType = (typeof VIEWER_EVENT_TYPES)[number];

/** Types that exist in the v1 vocabulary but a viewer build must not emit.
 *  Held as data so the reason is greppable from the test that pins it. */
export const EXCLUDED_EVENT_TYPES = ["transcript"] as const;

/**
 * Vocabulary that must not appear in any viewer route, tool, schema, or help
 * string. Mirrors the Cloud set.
 *
 * `pause`, `resume` and `checkpoint` are here despite sounding benign: they are
 * exactly the first controller registry the specification defers, and a viewer
 * that can pause a run is a controller with a small vocabulary.
 */
export const FORBIDDEN_VIEWER_TERMS: ReadonlySet<string> = new Set([
  "command", "commands", "steer", "steering", "prompt", "prompts",
  "approve", "approval", "confirm", "dispatch", "dispatcher",
  "controller", "control", "keyboard", "mouse", "keystroke", "click",
  "terminal", "shell", "exec", "execute", "stdin", "clipboard",
  "pause", "resume", "throttle", "checkpoint", "requeue", "restart",
  "terminate", "kill", "cancel", "emergency", "stop",
  "mutate", "submit", "send",
]);

/**
 * Split an identifier into lowercase word tokens.
 *
 * Identifiers arrive in every naming style a route or schema might use:
 * `/rc/{id}/emergency_stop`, `rcSendCommand`, `RemoteControlCommandV1`,
 * `rc-session-pause`. Splitting on non-alphanumerics alone would treat
 * `emergency_stop` as one opaque word matching nothing — the Cloud side shipped
 * exactly that bug and its own tests caught it, so this mirror starts with the
 * fix rather than repeating the mistake.
 */
export function tokenize(value: string): string[] {
  const out: string[] = [];
  for (const chunk of String(value).split(/[^A-Za-z0-9]+/)) {
    if (!chunk) continue;
    for (const part of chunk.match(/[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+/g) ?? []) {
      out.push(part.toLowerCase());
    }
  }
  return out;
}

export class ViewerProfileViolation extends Error {}

/** True when the host is allowed to publish this event class. */
export function isViewerEventType(value: string): value is ViewerEventType {
  return (VIEWER_EVENT_TYPES as readonly string[]).includes(value);
}

export function assertViewerEventType(value: string): asserts value is ViewerEventType {
  if (!isViewerEventType(value)) {
    throw new ViewerProfileViolation(
      `event type ${JSON.stringify(value)} is not part of the viewer profile`,
    );
  }
}

/** The release artifact must expose exactly `["observe"]`. */
export function assertViewerCapabilities(capabilities: readonly string[]): void {
  const declared = [...capabilities];
  if (declared.length !== 1 || declared[0] !== "observe") {
    throw new ViewerProfileViolation(
      `viewer capabilities must be exactly ["observe"], got ${JSON.stringify(declared)}`,
    );
  }
}

/**
 * Refuse a route/tool/schema/help manifest carrying control vocabulary.
 *
 * Matched on word boundaries, so `/rc/sessions/{id}/commands` fails while
 * `/rc/sessions/{id}/recommended` does not.
 */
export function assertViewerManifest(manifest: readonly string[], surface: string): void {
  const offenders: string[] = [];
  for (const entry of manifest) {
    for (const word of tokenize(entry)) {
      if (FORBIDDEN_VIEWER_TERMS.has(word)) {
        offenders.push(`${JSON.stringify(entry)} contains ${JSON.stringify(word)}`);
      }
    }
  }
  if (offenders.length > 0) {
    throw new ViewerProfileViolation(
      `${surface} manifest exposes control vocabulary: ${offenders.join(", ")}`,
    );
  }
}

/** The canonical, sorted description a CI job can diff against the Cloud one. */
export function viewerManifest(): Record<string, unknown> {
  return {
    schema: "aether.rc_viewer_profile/1",
    capabilities: [...VIEWER_CAPABILITIES],
    grant_purpose: VIEWER_GRANT_PURPOSE,
    presence_roles: [...VIEWER_PRESENCE_ROLES].sort(),
    event_types: [...VIEWER_EVENT_TYPES].sort(),
    control_capable: false,
  };
}
