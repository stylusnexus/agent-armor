import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm } from 'fs/promises';
import { createHash } from 'crypto';
import { join } from 'path';
import { tmpdir } from 'os';

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
    const { REQUIRED_MODEL_FILES } = await import('../src/constants');
    for (const file of REQUIRED_MODEL_FILES) {
      await writeFile(join(tempDir, file), 'mock-content');
    }
    const result = await resolveModel({ modelDir: tempDir });
    expect(result.modelDir).toBe(tempDir);
    expect(result.modelPath).toContain('model_quantized.onnx');
  });

  it('throws MODEL_NOT_FOUND when modelDir missing required files', async () => {
    const { resolveModel } = await import('../src/model-manager');
    await writeFile(join(tempDir, 'tokenizer.json'), '{}');
    await expect(resolveModel({ modelDir: tempDir })).rejects.toThrow('model_quantized.onnx');
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
    const { REQUIRED_MODEL_FILES } = await import('../src/constants');
    for (const file of REQUIRED_MODEL_FILES) {
      await writeFile(join(tempDir, file), 'mock-content');
    }
    await expect(validateModelDir(tempDir)).resolves.toBeUndefined();
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
    const digestOfContent = createHash('sha256')
      .update('some-content')
      .digest('hex');
    // Default path uses MODEL_CHECKSUM; result tracks whether the content
    // happens to match it (it does not), independent of placeholder state.
    const result = await verifyChecksum(filePath);
    expect(result).toBe(
      MODEL_CHECKSUM.startsWith('PLACEHOLDER') ||
        digestOfContent === MODEL_CHECKSUM,
    );
  });
});
