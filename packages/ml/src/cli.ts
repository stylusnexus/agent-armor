import { readdir, rm, stat } from 'fs/promises';
import { join } from 'path';
import { mkdirSync, copyFileSync } from 'fs';

import { getDefaultCacheDir, REQUIRED_MODEL_FILES, MODEL_VERSION } from './constants';
import { resolveModel } from './model-manager';

const COMMANDS: Record<string, string> = {
  download: 'Download model to a directory',
  'clear-cache': 'Clear cached models',
  'cache-info': 'Show cache directory and contents',
};

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    console.log('agentarmor-ml — ML classifier tools for Agent Armor\n');
    console.log('Commands:');
    for (const [cmd, desc] of Object.entries(COMMANDS)) {
      console.log(`  ${cmd.padEnd(15)} ${desc}`);
    }
    console.log('\nOptions:');
    console.log('  --dir <path>   Target directory for download');
    console.log('  --quiet        Suppress progress, output only final path');
    return;
  }

  switch (command) {
    case 'download': await cmdDownload(args.slice(1)); break;
    case 'clear-cache': await cmdClearCache(); break;
    case 'cache-info': await cmdCacheInfo(); break;
    default:
      console.error(`Unknown command: ${command}`);
      process.exit(1);
  }
}

async function cmdDownload(args: string[]): Promise<void> {
  const dirIndex = args.indexOf('--dir');
  const quiet = args.includes('--quiet');
  const dir = dirIndex >= 0 ? args[dirIndex + 1] : undefined;

  if (!dir) {
    console.error('Error: --dir <path> is required');
    process.exit(1);
  }

  const onProgress = quiet ? undefined : (received: number, total: number) => {
    if (total > 0) {
      const pct = ((received / total) * 100).toFixed(1);
      process.stdout.write(`\rDownloading... ${pct}% (${(received / 1e6).toFixed(1)}/${(total / 1e6).toFixed(1)} MB)`);
    }
  };

  try {
    // First, ensure model is in cache
    const result = await resolveModel({
      enabled: true,
      download: { onProgress },
    });

    // Copy from cache to target dir
    const resolvedDir = join(process.cwd(), dir);
    mkdirSync(resolvedDir, { recursive: true });
    for (const file of REQUIRED_MODEL_FILES) {
      const src = join(result.modelDir, file);
      const dest = join(resolvedDir, file);
      copyFileSync(src, dest);
    }

    if (!quiet) console.log('');
    console.log(quiet ? join(resolvedDir, 'model_quantized.onnx') : `Model downloaded to: ${resolvedDir}`);
  } catch (err) {
    console.error(`\nDownload failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

async function cmdClearCache(): Promise<void> {
  const cacheDir = getDefaultCacheDir();
  try {
    await rm(cacheDir, { recursive: true, force: true });
    console.log(`Cache cleared: ${cacheDir}`);
  } catch (err) {
    console.error(`Failed to clear cache: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

async function cmdCacheInfo(): Promise<void> {
  const cacheDir = getDefaultCacheDir();
  console.log(`Cache directory: ${cacheDir}`);
  console.log(`Model version: ${MODEL_VERSION}`);
  try {
    const files = await readdir(cacheDir);
    let totalSize = 0;
    for (const file of files) {
      const s = await stat(join(cacheDir, file));
      totalSize += s.size;
      console.log(`  ${file} (${(s.size / 1e6).toFixed(1)} MB)`);
    }
    console.log(`Total: ${(totalSize / 1e6).toFixed(1)} MB`);
  } catch {
    console.log('  (empty or not yet downloaded)');
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
