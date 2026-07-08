import { readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/** Extensions/filenames scanned by default when a directory is passed. */
export const DEFAULT_INCLUDE_EXTENSIONS = ['.md', '.txt', '.json', '.cursorrules'];

/** Directory names never recursed into, regardless of include filters. */
const DEFAULT_EXCLUDE_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage']);

function matchesInclude(fileName: string, includeExtensions: string[]): boolean {
  return includeExtensions.some(
    (ext) => fileName === ext || fileName.toLowerCase().endsWith(ext.toLowerCase())
  );
}

function walkDir(dir: string, includeExtensions: string[]): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (DEFAULT_EXCLUDE_DIRS.has(entry.name)) continue;
      out.push(...walkDir(path.join(dir, entry.name), includeExtensions));
    } else if (entry.isFile() && matchesInclude(entry.name, includeExtensions)) {
      out.push(path.join(dir, entry.name));
    }
  }
  return out;
}

/**
 * Resolves CLI path arguments to a flat list of files.
 * - A file path is always included, regardless of extension (explicit request wins).
 * - A directory path is recursed, filtered by `includeExtensions`
 *   (default: {@link DEFAULT_INCLUDE_EXTENSIONS}), skipping node_modules/.git/dist/coverage.
 */
export function discoverFiles(paths: string[], includeExtensions?: string[]): string[] {
  const extensions = includeExtensions ?? DEFAULT_INCLUDE_EXTENSIONS;
  const out: string[] = [];
  for (const p of paths) {
    const resolved = path.resolve(p);
    const stats = statSync(resolved);
    if (stats.isDirectory()) {
      out.push(...walkDir(resolved, extensions));
    } else {
      out.push(resolved);
    }
  }
  return out;
}
