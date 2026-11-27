// Temporary: lets typedoc run on minimatch 11, the first release without
// GHSA-g3hv-75wg-m249. typedoc 0.28.20 calls matchOne(), which 11 removed.
// Remove this script, its test and the `typedoc` override once a typedoc
// release includes https://github.com/TypeStrong/typedoc/pull/3151 (#410).
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ORIGINAL = `      return mini.set.some((row) => mini.matchOne(
        childPath,
        row,
        /* partial */
        true
      ));
`;

export const PATCHED = `      return new Minimatch2(pattern, { partial: true, flipNegate: true }).match(childPath.join("/"));
`;

export function patchSource(source) {
  if (source.includes(PATCHED)) return source;
  if (!source.includes(ORIGINAL)) {
    throw new Error('Cannot patch typedoc: its code has changed. See scripts/patch-typedoc.mjs.');
  }
  return source.replace(ORIGINAL, () => PATCHED);
}

// Run from the folder whose node_modules holds typedoc. Only `docs:build` runs
// this, never an install hook, so it can't run on a user's machine.
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const file = resolve('node_modules/typedoc/dist/node-utils.js');
  const source = readFileSync(file, 'utf8');
  const patched = patchSource(source);
  if (patched !== source) writeFileSync(file, patched);
}
