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

/** Normalize a host for comparison: lowercase, drop a single trailing dot
 * (FQDN form `api.example.com.` and `api.example.com` are the same target). */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.$/, "");
}

/** Host implied by `args.url` (the field the tool actually fetches), or null. */
function hostFromUrl(args: Record<string, unknown>): string | null {
  if (typeof args.url !== "string") return null;
  try {
    return normalizeHost(new URL(args.url).hostname);
  } catch {
    return null;
  }
}

/** Host explicitly declared in `args.host`, or null. */
function hostFromArg(args: Record<string, unknown>): string | null {
  if (typeof args.host === "string" && args.host.length > 0) {
    return normalizeHost(args.host);
  }
  return null;
}

/** True if `host` is permitted by `allowed` (exact or `*.domain` subdomain;
 * a `*.domain` entry also matches the apex `domain`). */
function hostAllowed(host: string, allowed: string[]): boolean {
  return allowed.some((entry) => {
    const e = normalizeHost(entry);
    if (e.startsWith("*.")) {
      const apex = e.slice(2); // 'example.com'
      return host === apex || host.endsWith("." + apex);
    }
    return host === e;
  });
}

/** True if a path is absolute (POSIX `/…`, UNC/`\…`, or Windows `C:\…`). */
function isAbsolutePath(path: string): boolean {
  return /^[\\/]/.test(path) || /^[A-Za-z]:/.test(path);
}

/**
 * Return a refusal reason if a path cannot be safely confined, else null.
 *
 * The gate validates strings it never resolves against a trusted base, so it
 * must fail closed on anything it cannot reason about literally: absolute paths
 * (un-confinable without a base), parent-directory traversal in any all-dots
 * form (`..`, `...`, `....`), percent-encoding (the caller must pass a decoded
 * path — `%2e%2e` would otherwise slip past), and non-ASCII (unicode dot/slash
 * confusables). Callers are expected to pass already-decoded, normalized paths.
 */
function pathPolicyViolation(path: string): string | null {
  if (path.includes("%")) {
    return "contains percent-encoding; pass an already-decoded path";
  }
  if (/[^\x20-\x7e]/.test(path)) {
    return "contains non-ASCII characters";
  }
  if (isAbsolutePath(path)) {
    return "is absolute; the gate has no trusted base to confine it against";
  }
  if (path.split(/[\\/]/).some((seg) => /^\.{2,}$/.test(seg))) {
    return "contains a parent-directory ('..') segment; traversal is not permitted";
  }
  return null;
}

/** True if the request args signal a write/mutating operation. Known-signal
 * check (not exhaustive): `mode`, `write`, `readOnly`, and HTTP `method`. */
function signalsWrite(args: Record<string, unknown>): boolean {
  const mode = typeof args.mode === "string" ? args.mode.toLowerCase() : "";
  if (mode === "write" || mode === "read-write" || mode === "readwrite") {
    return true;
  }
  if (args.write === true) return true;
  if (args.readOnly === false || args.readonly === false) return true;
  // Any non-safe HTTP method present implies a write.
  if (typeof args.method === "string") {
    const m = args.method.toUpperCase();
    if (m !== "GET" && m !== "HEAD" && m !== "OPTIONS") return true;
  }
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
    const urlHost = hostFromUrl(args);
    const argHost = hostFromArg(args);
    // If both are present and disagree, the request is ambiguous about what it
    // will actually contact — deny rather than trust the weaker signal.
    if (urlHost && argHost && urlHost !== argHost) {
      return {
        ok: false,
        reason: `Ambiguous host for "${rule.tool}": args.url host "${urlHost}" disagrees with args.host "${argHost}".`,
      };
    }
    // Prefer the URL host: it is what an HTTP tool actually fetches.
    const host = urlHost ?? argHost;
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
    // Fail closed on anything we cannot confine literally (absolute paths,
    // traversal in any form, percent-encoding, non-ASCII). See
    // pathPolicyViolation — the gate never resolves paths against a base.
    const violation = pathPolicyViolation(path);
    if (violation) {
      return {
        ok: false,
        reason: `Path "${path}" ${violation}.`,
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
