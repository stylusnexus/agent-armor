import { readdirSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';

/** Extensions/filenames scanned by default when a directory is passed. */
export const DEFAULT_INCLUDE_EXTENSIONS = ['.md', '.txt', '.json', '.cursorrules'];

/** Directory names never recursed into, regardless of include filters. */
const DEFAULT_EXCLUDE_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage']);

function matchesInclude(fileName: string, includeExtensions: string[]): boolean {
  return includeExtensions.some(
    (ext) => fileName === ext || fileName.toLowerCase().endsWith(ext.toLowerCase()),
  );
}

function walkDir(dir: string, includeExtensions: string[], visited: Set<string>): string[] {
  let realDir: string;
  try {
    realDir = realpathSync(dir);
  } catch {
    return [];
  }
  if (visited.has(realDir)) return [];
  visited.add(realDir);
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (DEFAULT_EXCLUDE_DIRS.has(entry.name)) continue;
      out.push(...walkDir(entryPath, includeExtensions, visited));
    } else if (entry.isSymbolicLink()) {
      // stat follows the link, allowing symlinked config files and directories.
      try {
        const target = statSync(entryPath);
        if (target.isDirectory()) {
          if (!DEFAULT_EXCLUDE_DIRS.has(entry.name)) {
            out.push(...walkDir(entryPath, includeExtensions, visited));
          }
        } else if (target.isFile() && matchesInclude(entry.name, includeExtensions)) {
          out.push(entryPath);
        }
      } catch {
        // Dangling links are not scan inputs.
      }
    } else if (entry.isFile() && matchesInclude(entry.name, includeExtensions)) {
      out.push(entryPath);
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
  const visited = new Set<string>();
  for (const p of paths) {
    const resolved = path.resolve(p);
    const stats = statSync(resolved);
    if (stats.isDirectory()) {
      out.push(...walkDir(resolved, extensions, visited));
    } else {
      out.push(resolved);
    }
  }
  return out;
}
