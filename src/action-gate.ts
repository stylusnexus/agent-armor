/**
 * Pre-execution action gate (#57): a positive-allowlist admissibility check.
 *
 * Where the detector pipeline answers "does this content look adversarial?",
 * the gate answers "is this agent allowed to run this action right now?". It is
 * deterministic and binary — no confidence scores, no strictness — and it fails
 * closed: an empty (or absent) allowlist denies everything.
 */

import type { ActionRequest, ActionRule, ActionVerdict } from "./types";
import { matchAnyGlob } from "./glob";

/**
 * Thrown by integrators when a request is inadmissible. Provided for ergonomics
 * so callers can `throw new ActionBlockedError(verdict.reason)` to fail closed.
 */
export class ActionBlockedError extends Error {
  constructor(reason?: string) {
    super(reason ?? "Action blocked by Agent Armor action gate");
    this.name = "ActionBlockedError";
  }
}

/** Read the request host from `args.host` or the hostname of `args.url`. */
function extractHost(args: Record<string, unknown>): string | null {
  if (typeof args.host === "string" && args.host.length > 0) {
    return args.host.toLowerCase();
  }
  if (typeof args.url === "string") {
    try {
      return new URL(args.url).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  return null;
}

/** True if `host` is permitted by `allowed` (exact or `*.domain` subdomain). */
function hostAllowed(host: string, allowed: string[]): boolean {
  return allowed.some((entry) => {
    const e = entry.toLowerCase();
    if (e.startsWith("*.")) {
      const apex = e.slice(2); // 'example.com'
      return host === apex || host.endsWith("." + apex);
    }
    return host === e;
  });
}

/** True if any segment of the path is `..` (parent-directory traversal). */
function hasTraversal(path: string): boolean {
  return path.split(/[\\/]/).some((seg) => seg === "..");
}

/** True if the request args signal a write/mutating operation. */
function signalsWrite(args: Record<string, unknown>): boolean {
  const mode = typeof args.mode === "string" ? args.mode.toLowerCase() : "";
  if (mode === "write" || mode === "read-write" || mode === "readwrite") {
    return true;
  }
  if (args.write === true) return true;
  if (args.readOnly === false || args.readonly === false) return true;
  return false;
}

/**
 * Check a single rule against the request args, returning either admission or a
 * specific reason for refusal. The tool name is assumed already matched.
 */
function ruleAdmits(
  rule: ActionRule,
  args: Record<string, unknown>
): { ok: true } | { ok: false; reason: string } {
  if (rule.hosts) {
    const host = extractHost(args);
    if (host === null) {
      return {
        ok: false,
        reason: `Tool "${rule.tool}" requires a host (args.url or args.host); none was provided.`,
      };
    }
    if (!hostAllowed(host, rule.hosts)) {
      return {
        ok: false,
        reason: `Host "${host}" is not in the allowlist for "${rule.tool}" (allowed: ${rule.hosts.join(", ")}).`,
      };
    }
  }

  if (rule.paths) {
    const path = typeof args.path === "string" ? args.path : null;
    if (path === null) {
      return {
        ok: false,
        reason: `Tool "${rule.tool}" requires a path (args.path); none was provided.`,
      };
    }
    // Fail closed on traversal: a `..` segment can escape an allowlisted
    // directory (e.g. `./data/../../etc/passwd` would otherwise satisfy
    // `./data/**`). We deny rather than resolve, since there is no trusted base.
    if (hasTraversal(path)) {
      return {
        ok: false,
        reason: `Path "${path}" contains a parent-directory ('..') segment; traversal is not permitted.`,
      };
    }
    if (!matchAnyGlob(rule.paths, path)) {
      return {
        ok: false,
        reason: `Path "${path}" is outside the allowed paths for "${rule.tool}" (allowed: ${rule.paths.join(", ")}).`,
      };
    }
  }

  if (rule.mode === "read-only" && signalsWrite(args)) {
    return {
      ok: false,
      reason: `Tool "${rule.tool}" is restricted to read-only; the request signals a write.`,
    };
  }

  return { ok: true };
}

/**
 * Evaluate a proposed action against an allowlist. Pure and deterministic.
 *
 * Default-deny: returns inadmissible if `rules` is empty, if no rule's `tool`
 * matches, or if every matching rule rejects the args. When more than one rule
 * shares a tool name, the request is admissible if ANY of them admits it; the
 * reported reason is from the last rule tried.
 */
export function evaluateAction(
  req: ActionRequest,
  rules: ActionRule[]
): ActionVerdict {
  if (!rules || rules.length === 0) {
    return {
      admissible: false,
      reason: "No actions are allowlisted; the action gate denies all (fail closed).",
    };
  }

  const candidates = rules.filter((r) => r.tool === req.tool);
  if (candidates.length === 0) {
    return {
      admissible: false,
      reason: `Tool "${req.tool}" is not on the allowlist.`,
    };
  }

  const args = req.args ?? {};
  let lastReason = `Tool "${req.tool}" did not satisfy any matching rule.`;
  for (const rule of candidates) {
    const result = ruleAdmits(rule, args);
    if (result.ok) {
      return { admissible: true, matchedRule: rule };
    }
    lastReason = result.reason;
  }
  return { admissible: false, reason: lastReason };
}
