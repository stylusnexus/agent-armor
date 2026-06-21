import { describe, it, expect } from 'vitest';
import {
  matchGlob,
  matchAnyGlob,
  expandBraces,
  normalizePath,
  globToRegExp,
} from '../glob';

describe('glob matcher (#57)', () => {
  describe('single-star (within a segment)', () => {
    it('matches any run inside one segment', () => {
      expect(matchGlob('*.ts', 'index.ts')).toBe(true);
      expect(matchGlob('data/*.json', 'data/users.json')).toBe(true);
      expect(matchGlob('a*b', 'aXXXb')).toBe(true);
      expect(matchGlob('a*b', 'ab')).toBe(true);
    });

    it('does NOT cross a slash', () => {
      expect(matchGlob('*.ts', 'src/index.ts')).toBe(false);
      expect(matchGlob('data/*.json', 'data/sub/users.json')).toBe(false);
      expect(matchGlob('src/*', 'src/a/b')).toBe(false);
    });
  });

  describe('globstar ** (crosses segments)', () => {
    it('matches zero or more middle segments', () => {
      expect(matchGlob('a/**/b', 'a/b')).toBe(true);
      expect(matchGlob('a/**/b', 'a/x/b')).toBe(true);
      expect(matchGlob('a/**/b', 'a/x/y/b')).toBe(true);
      expect(matchGlob('a/**/b', 'a/x/y/c')).toBe(false);
    });

    it('matches as a leading segment (incl. zero)', () => {
      expect(matchGlob('**/b', 'b')).toBe(true);
      expect(matchGlob('**/b', 'x/b')).toBe(true);
      expect(matchGlob('**/b', 'x/y/b')).toBe(true);
      expect(matchGlob('**/*.ts', 'src/deep/file.ts')).toBe(true);
    });

    it('matches as a trailing segment (incl. zero)', () => {
      expect(matchGlob('a/**', 'a')).toBe(true);
      expect(matchGlob('a/**', 'a/x')).toBe(true);
      expect(matchGlob('a/**', 'a/x/y')).toBe(true);
      expect(matchGlob('a/**', 'b/x')).toBe(false);
    });

    it('bare ** matches everything', () => {
      expect(matchGlob('**', 'anything/at/all')).toBe(true);
      expect(matchGlob('**', 'x')).toBe(true);
    });

    it('the ./data/** rule from the issue example', () => {
      expect(matchGlob('./data/**', 'data/users.json')).toBe(true);
      expect(matchGlob('./data/**', 'data/sub/dir/file.csv')).toBe(true);
      expect(matchGlob('./data/**', 'secrets/keys.txt')).toBe(false);
    });
  });

  describe('question mark', () => {
    it('matches exactly one non-slash char', () => {
      expect(matchGlob('file?.txt', 'file1.txt')).toBe(true);
      expect(matchGlob('file?.txt', 'file.txt')).toBe(false);
      expect(matchGlob('file?.txt', 'file12.txt')).toBe(false);
      expect(matchGlob('a/?/b', 'a//b')).toBe(false);
    });
  });

  describe('character classes', () => {
    it('matches ranges and sets', () => {
      expect(matchGlob('file[0-9].txt', 'file7.txt')).toBe(true);
      expect(matchGlob('file[0-9].txt', 'fileA.txt')).toBe(false);
      expect(matchGlob('[abc]x', 'bx')).toBe(true);
      expect(matchGlob('[abc]x', 'dx')).toBe(false);
    });

    it('supports negation with ! and ^', () => {
      expect(matchGlob('file[!0-9].txt', 'fileA.txt')).toBe(true);
      expect(matchGlob('file[!0-9].txt', 'file7.txt')).toBe(false);
      expect(matchGlob('file[^x].txt', 'filex.txt')).toBe(false);
    });

    it('a class never matches a slash', () => {
      expect(matchGlob('a[b/]c', 'a/c')).toBe(false);
    });
  });

  describe('brace alternation', () => {
    it('expands top-level alternatives', () => {
      expect(matchGlob('*.{js,ts}', 'index.ts')).toBe(true);
      expect(matchGlob('*.{js,ts}', 'index.js')).toBe(true);
      expect(matchGlob('*.{js,ts}', 'index.go')).toBe(false);
    });

    it('handles nested braces', () => {
      expect(expandBraces('a{b,c{d,e}}')).toEqual(['ab', 'acd', 'ace']);
    });

    it('treats a comma-less group as literal', () => {
      expect(expandBraces('{foo}')).toEqual(['{foo}']);
    });
  });

  describe('escaping and literals', () => {
    it('treats backslash-escaped metachars as literal', () => {
      expect(matchGlob('a\\*b', 'a*b')).toBe(true);
      expect(matchGlob('a\\*b', 'aXb')).toBe(false);
    });

    it('escapes regex-special chars in literal positions', () => {
      expect(matchGlob('a.b+c', 'a.b+c')).toBe(true);
      expect(matchGlob('a.b+c', 'aXbXc')).toBe(false);
      expect(matchGlob('price($).txt', 'price($).txt')).toBe(true);
    });
  });

  describe('path normalization', () => {
    it('strips ./ and collapses // and trailing /', () => {
      expect(normalizePath('./data//x/')).toBe('data/x');
      expect(matchGlob('data/x', './data//x/')).toBe(true);
    });
  });

  describe('helpers', () => {
    it('matchAnyGlob ORs a list of patterns', () => {
      expect(matchAnyGlob(['src/**', 'docs/**'], 'docs/a/b.md')).toBe(true);
      expect(matchAnyGlob(['src/**', 'docs/**'], 'lib/a.js')).toBe(false);
    });

    it('globToRegExp produces an anchored pattern', () => {
      const re = globToRegExp('a*');
      expect(re.test('ab')).toBe(true);
      expect(re.test('xab')).toBe(false);
    });
  });
});
