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
  });

  describe('path constraint', () => {
    it('admits a path inside an allowed glob', () => {
      expect(armor.checkAction({ tool: 'fs.read', args: { path: './data/users/list.json' } }).admissible).toBe(true);
      expect(armor.checkAction({ tool: 'fs.read', args: { path: 'logs/app.log' } }).admissible).toBe(true);
    });

    it('blocks a path outside the allowed globs', () => {
      const v = armor.checkAction({ tool: 'fs.read', args: { path: '/etc/passwd' } });
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
