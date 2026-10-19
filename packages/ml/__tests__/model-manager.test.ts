import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { createHash } from 'crypto';
import { join } from 'path';
import { tmpdir } from 'os';

const TEST_FILES = ['model_quantized.onnx', 'tokenizer.json', 'label_map.json'] as const;
type TestChecksums = Record<(typeof TEST_FILES)[number], string>;

async function writeTestArtifacts(
  dir: string,
  overrides: Partial<Record<(typeof TEST_FILES)[number], string>> = {},
): Promise<TestChecksums> {
  const checksums = {} as TestChecksums;
  for (const file of TEST_FILES) {
    const contents = overrides[file] ?? `mock:${file}`;
    await writeFile(join(dir, file), contents);
    checksums[file] = createHash('sha256').update(contents).digest('hex');
  }
  return checksums;
}

describe('resolveModel', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'agentarmor-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('resolves from modelDir when all required files exist', async () => {
    const { resolveModel } = await import('../src/model-manager');
    const modelChecksums = await writeTestArtifacts(tempDir);
    const result = await resolveModel({ modelDir: tempDir, modelChecksums });
    expect(result.modelDir).toBe(tempDir);
    expect(result.modelPath).toContain('model_quantized.onnx');
  });

  it.each(['tokenizer.json', 'label_map.json'])(
    'rejects a tampered custom %s with CHECKSUM_MISMATCH',
    async (file) => {
      const { resolveModel } = await import('../src/model-manager');
      const modelChecksums = await writeTestArtifacts(tempDir);
      await writeFile(join(tempDir, file), 'tampered');
      await expect(resolveModel({ modelDir: tempDir, modelChecksums })).rejects.toMatchObject({
        code: 'CHECKSUM_MISMATCH',
      });
    },
  );

  it('throws MODEL_NOT_FOUND when modelDir missing required files', async () => {
    const { resolveModel } = await import('../src/model-manager');
    await writeFile(join(tempDir, 'tokenizer.json'), '{}');
    await expect(resolveModel({ modelDir: tempDir })).rejects.toThrow('model_quantized.onnx');
  });
});

describe('getModelCacheDir', () => {
  it('isolates custom sources and checksums from the pinned release cache', async () => {
    const { getModelCacheDir } = await import('../src/model-manager');
    const { REQUIRED_MODEL_CHECKSUMS } = await import('../src/constants');
    const customChecksums = { ...REQUIRED_MODEL_CHECKSUMS, 'tokenizer.json': 'a'.repeat(64) };

    expect(getModelCacheDir({})).not.toBe(getModelCacheDir({ modelChecksums: customChecksums }));
    expect(getModelCacheDir({ modelUrl: 'https://models.example/a' })).not.toBe(
      getModelCacheDir({ modelUrl: 'https://models.example/b' }),
    );
  });
});

describe('validateModelDir', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'agentarmor-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('passes when all required files exist', async () => {
    const { validateModelDir } = await import('../src/model-manager');
    const checksums = await writeTestArtifacts(tempDir);
    await expect(validateModelDir(tempDir, checksums)).resolves.toBeUndefined();
  });

  it('throws with MODEL_NOT_FOUND code when files are missing', async () => {
    const { validateModelDir } = await import('../src/model-manager');
    const { AgentArmorModelError } = await import('../src/errors');
    try {
      await validateModelDir(tempDir);
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AgentArmorModelError);
      expect((err as InstanceType<typeof AgentArmorModelError>).code).toBe('MODEL_NOT_FOUND');
    }
  });

  it('lists missing files in the error message', async () => {
    const { validateModelDir } = await import('../src/model-manager');
    await writeFile(join(tempDir, 'tokenizer.json'), '{}');
    try {
      await validateModelDir(tempDir);
      expect.fail('should have thrown');
    } catch (err) {
      const message = (err as Error).message;
      // The "Missing required model files" portion should list the missing ones
      const missingPart = message.split('Required files:')[0];
      expect(missingPart).toContain('model_quantized.onnx');
      expect(missingPart).toContain('label_map.json');
      expect(missingPart).not.toContain('tokenizer.json');
    }
  });
});

describe('verifyChecksum', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'agentarmor-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('skips verification (returns true) when expected checksum is a placeholder', async () => {
    const { verifyChecksum } = await import('../src/model-manager');
    const filePath = join(tempDir, 'test-model.onnx');
    await writeFile(filePath, 'some-content');
    const result = await verifyChecksum(filePath, 'PLACEHOLDER_SHA256');
    expect(result).toBe(true);
  });

  it('returns true when the file digest matches the expected checksum', async () => {
    const { verifyChecksum } = await import('../src/model-manager');
    const content = 'some-content';
    const expected = createHash('sha256').update(content).digest('hex');
    const filePath = join(tempDir, 'test-model.onnx');
    await writeFile(filePath, content);
    const result = await verifyChecksum(filePath, expected);
    expect(result).toBe(true);
  });

  it('returns false when the file digest does not match the expected checksum', async () => {
    const { verifyChecksum } = await import('../src/model-manager');
    const filePath = join(tempDir, 'test-model.onnx');
    await writeFile(filePath, 'some-content');
    const result = await verifyChecksum(filePath, 'a'.repeat(64));
    expect(result).toBe(false);
  });

  it('verifies against the shipped MODEL_CHECKSUM by default', async () => {
    const { verifyChecksum } = await import('../src/model-manager');
    const { MODEL_CHECKSUM } = await import('../src/constants');
    const filePath = join(tempDir, 'test-model.onnx');
    await writeFile(filePath, 'some-content');
    const digestOfContent = createHash('sha256').update('some-content').digest('hex');
    // Default path uses MODEL_CHECKSUM; result tracks whether the content
    // happens to match it (it does not), independent of placeholder state.
    const result = await verifyChecksum(filePath);
    expect(result).toBe(
      MODEL_CHECKSUM.startsWith('PLACEHOLDER') || digestOfContent === MODEL_CHECKSUM,
    );
  });
});

describe('verifyRequiredModelChecksums', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'agentarmor-integrity-test-'));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it.each(['tokenizer.json', 'label_map.json'])(
    'rejects a tampered %s with CHECKSUM_MISMATCH',
    async (tamperedFile) => {
      const { verifyRequiredModelChecksums } = await import('../src/model-manager');
      const checksums = await writeTestArtifacts(tempDir);
      await writeFile(join(tempDir, tamperedFile), 'tampered');

      await expect(verifyRequiredModelChecksums(tempDir, checksums)).rejects.toMatchObject({
        code: 'CHECKSUM_MISMATCH',
      });
    },
  );
});
