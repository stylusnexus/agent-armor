import { describe, it, expect } from 'vitest';
import { AgentArmor } from '../agent-armor';
import { evaluateAction, ActionBlockedError } from '../action-gate';
import type { ActionRule } from '../types';

const RULES: ActionRule[] = [
  { tool: 'http.get', hosts: ['api.internal.example.com', '*.trusted.example'] },
  { tool: 'fs.read', paths: ['./data/**', 'logs/*.log'] },
  { tool: 'db.query', mode: 'read-only' },
];

describe('action gate / checkAction (#57)', () => {
  const armor = AgentArmor.regexOnly({ allowedActions: RULES });

  describe('default-deny posture', () => {
    it('blocks a tool not present in the allowlist', () => {
      const v = armor.checkAction({ tool: 'http.post', args: { url: 'https://x' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/not on the allowlist/);
    });

    it('empty allowlist blocks everything (fail closed, not allow-all)', () => {
      const locked = AgentArmor.regexOnly({ allowedActions: [] });
      const v = locked.checkAction({ tool: 'http.get', args: { url: 'https://api.internal.example.com/x' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/fail closed/);
    });

    it('no allowedActions configured at all = deny', () => {
      const v = AgentArmor.regexOnly().checkAction({ tool: 'fs.read', args: { path: './data/x' } });
      expect(v.admissible).toBe(false);
    });
  });

  describe('exact-match admission', () => {
    it('admits a tool matching a rule with no extra constraints absent', () => {
      const v = armor.checkAction({ tool: 'db.query', args: { sql: 'SELECT 1', mode: 'read-only' } });
      expect(v.admissible).toBe(true);
      expect(v.matchedRule?.tool).toBe('db.query');
    });
  });

  describe('host constraint', () => {
    it('admits an allowed exact host', () => {
      const v = armor.checkAction({ tool: 'http.get', args: { url: 'https://api.internal.example.com/v1/data' } });
      expect(v.admissible).toBe(true);
    });

    it('admits a wildcard subdomain and its apex', () => {
      expect(armor.checkAction({ tool: 'http.get', args: { url: 'https://a.trusted.example/x' } }).admissible).toBe(true);
      expect(armor.checkAction({ tool: 'http.get', args: { url: 'https://trusted.example/x' } }).admissible).toBe(true);
    });

    it('blocks a host not in the list', () => {
      const v = armor.checkAction({ tool: 'http.get', args: { url: 'https://evil.example/exfil' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/not in the allowlist/);
    });

    it('blocks when no host can be determined', () => {
      const v = armor.checkAction({ tool: 'http.get', args: {} });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/requires a host/);
    });

    it('reads args.host directly when no url is present', () => {
      const v = armor.checkAction({ tool: 'http.get', args: { host: 'api.internal.example.com' } });
      expect(v.admissible).toBe(true);
    });

    it('prefers the url host and denies when args.host disagrees with it (C1)', () => {
      // args.host names an allowed host, but the url targets an evil one.
      const v = armor.checkAction({
        tool: 'http.get',
        args: { host: 'api.internal.example.com', url: 'https://evil.example/' },
      });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/[Aa]mbiguous host/);
    });

    it('matches a trailing-dot FQDN against the allowlist (I3)', () => {
      const v = armor.checkAction({ tool: 'http.get', args: { host: 'api.internal.example.com.' } });
      expect(v.admissible).toBe(true);
    });
  });

  describe('path constraint', () => {
    it('admits a path inside an allowed glob', () => {
      expect(armor.checkAction({ tool: 'fs.read', args: { path: './data/users/list.json' } }).admissible).toBe(true);
      expect(armor.checkAction({ tool: 'fs.read', args: { path: 'logs/app.log' } }).admissible).toBe(true);
    });

    it('blocks a relative path outside the allowed globs', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'secrets/keys.txt' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/outside the allowed paths/);
    });

    it('blocks logs/*.log from matching a nested file (single-star is segment-bound)', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'logs/2026/app.log' } });
      expect(v.admissible).toBe(false);
    });

    it('blocks when no path is provided', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: {} });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/requires a path/);
    });

    it('blocks path traversal even when the glob would otherwise match (fail closed)', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: './data/../../../etc/passwd' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/traversal is not permitted/);
    });

    it('blocks traversal with backslash separators too', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'data\\..\\..\\secrets' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/traversal/);
    });

    it('blocks an absolute path even when a ** rule would match (C2)', () => {
      const wide = AgentArmor.regexOnly({ allowedActions: [{ tool: 'fs.read', paths: ['**'] }] });
      expect(wide.checkAction({ tool: 'fs.read', args: { path: '/etc/passwd' } }).admissible).toBe(false);
      expect(wide.checkAction({ tool: 'fs.read', args: { path: 'C:\\Windows\\system32' } }).admissible).toBe(false);
    });

    it('blocks percent-encoded traversal (I1)', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'data/%2e%2e/%2e%2e/etc/passwd' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/percent-encoding/);
    });

    it('blocks non-ASCII unicode-dot confusables (I1)', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'data/․․/secret' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/non-ASCII/);
    });

    it('blocks all-dots segments longer than two (... ....)', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: 'data/.../secret' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/traversal/);
    });

    it('blocks a leading ~ even when a ** rule would match (home-dir expansion escapes)', () => {
      const wide = AgentArmor.regexOnly({ allowedActions: [{ tool: 'fs.read', paths: ['**'] }] });
      const v = wide.checkAction({ tool: 'fs.read', args: { path: '~/.ssh/id_rsa' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/home-directory/);
    });

    it('blocks URL/stream wrappers like php:// and file:// (I1)', () => {
      const wide = AgentArmor.regexOnly({ allowedActions: [{ tool: 'fs.read', paths: ['**'] }] });
      expect(wide.checkAction({ tool: 'fs.read', args: { path: 'php://input' } }).admissible).toBe(false);
      const v = wide.checkAction({ tool: 'fs.read', args: { path: 'file:///etc/passwd' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/scheme/);
    });
  });

  describe('mode constraint (read-only)', () => {
    it('admits an explicit read-only request', () => {
      expect(armor.checkAction({ tool: 'db.query', args: { mode: 'read-only' } }).admissible).toBe(true);
    });

    it('admits when no write is signalled', () => {
      expect(armor.checkAction({ tool: 'db.query', args: { sql: 'SELECT 1' } }).admissible).toBe(true);
    });

    it('blocks a write under read-only (mode=write)', () => {
      const v = armor.checkAction({ tool: 'db.query', args: { mode: 'write', sql: 'DELETE FROM t' } });
      expect(v.admissible).toBe(false);
      expect(v.reason).toMatch(/read-only/);
    });

    it('blocks a write under read-only (write:true and readOnly:false)', () => {
      expect(armor.checkAction({ tool: 'db.query', args: { write: true } }).admissible).toBe(false);
      expect(armor.checkAction({ tool: 'db.query', args: { readOnly: false } }).admissible).toBe(false);
    });

    it('treats a non-safe HTTP method as a write under read-only (I2)', () => {
      const ro = AgentArmor.regexOnly({ allowedActions: [{ tool: 'http', mode: 'read-only' }] });
      expect(ro.checkAction({ tool: 'http', args: { method: 'POST' } }).admissible).toBe(false);
      expect(ro.checkAction({ tool: 'http', args: { method: 'DELETE' } }).admissible).toBe(false);
      expect(ro.checkAction({ tool: 'http', args: { method: 'GET' } }).admissible).toBe(true);
    });
  });

  describe('multiple rules for one tool', () => {
    it('admits if any rule for the tool admits', () => {
      const rules: ActionRule[] = [
        { tool: 'http.get', hosts: ['a.example'] },
        { tool: 'http.get', hosts: ['b.example'] },
      ];
      const v = evaluateAction({ tool: 'http.get', args: { url: 'https://b.example/x' } }, rules);
      expect(v.admissible).toBe(true);
    });
  });

  describe('ActionBlockedError', () => {
    it('carries the verdict reason and the right name', () => {
      const err = new ActionBlockedError('Host "evil.example" is not allowed.');
      expect(err).toBeInstanceOf(Error);
      expect(err.name).toBe('ActionBlockedError');
      expect(err.message).toMatch(/evil.example/);
    });
  });
});
