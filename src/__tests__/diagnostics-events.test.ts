import { describe, it, expect, vi, afterEach } from 'vitest';
import { AgentArmor } from '../agent-armor';

describe('diagnostics events — backward compatibility (no `on` config)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('a detector-disabled-by-config toggle produces no console output (unchanged — detectorSkipped is new/additive)', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    new AgentArmor({ contentInjection: { hiddenHTML: false } });
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('session.accumulation requested still logs via console.warn exactly as before', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const armor = new AgentArmor({ session: { accumulation: true } });
    armor.scanSession([{ role: 'user', content: 'hello' }]);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('session.accumulation is not available'));
  });

  it('a detector throwing during scan still logs via console.warn exactly as before', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const throwingDetector = {
      id: 'throws-always',
      name: 'Throws Always',
      category: 'content-injection' as const,
      scan: () => {
        throw new Error('boom');
      },
      sanitize: (content: string) => content,
    };
    const armor = new AgentArmor({ customDetectors: [throwingDetector] });
    armor.scanSync('anything');
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Detector "throws-always" threw during scan: boom'));
  });
});

describe('diagnostics events — on.warn', () => {
  it('routes ML-unavailable through on.warn instead of console.warn', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onWarn = vi.fn();
    await AgentArmor.create({
      ml: { enabled: true, onUnavailable: 'warn-and-skip' },
      on: { warn: onWarn },
    });
    expect(onWarn).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining('ML classifier unavailable'),
        context: { detectorId: 'ml-classifier' },
      })
    );
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('routes accumulation-requested through on.warn instead of console.warn', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onWarn = vi.fn();
    const armor = new AgentArmor({ session: { accumulation: true }, on: { warn: onWarn } });
    armor.scanSession([{ role: 'user', content: 'hello' }]);
    expect(onWarn).toHaveBeenCalledWith(
      expect.objectContaining({ message: expect.stringContaining('session.accumulation is not available') })
    );
    expect(warnSpy).not.toHaveBeenCalled();
  });
});

describe('diagnostics events — on.error', () => {
  it('routes a detector-threw error through on.error instead of console.warn, with the real Error attached', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const onError = vi.fn();
    const throwingDetector = {
      id: 'throws-always',
      name: 'Throws Always',
      category: 'content-injection' as const,
      scan: () => {
        throw new Error('boom');
      },
      sanitize: (content: string) => content,
    };
    const armor = new AgentArmor({ customDetectors: [throwingDetector], on: { error: onError } });
    armor.scanSync('anything');
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({
        message: expect.stringContaining('threw during scan: boom'),
        error: expect.any(Error),
        context: { detectorId: 'throws-always' },
      })
    );
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it('routes an async-path detector-threw error through on.error', async () => {
    const onError = vi.fn();
    const throwingDetector = {
      id: 'throws-always-async',
      name: 'Throws Always Async',
      category: 'content-injection' as const,
      scan: () => {
        throw new Error('async boom');
      },
      sanitize: (content: string) => content,
    };
    const armor = new AgentArmor({ customDetectors: [throwingDetector], on: { error: onError } });
    await armor.scan('anything');
    expect(onError).toHaveBeenCalledWith(
      expect.objectContaining({ message: expect.stringContaining('async boom') })
    );
  });
});

describe('diagnostics events — on.detectorSkipped', () => {
  it('fires with reason "config-disabled" for a toggled-off detector', () => {
    const onDetectorSkipped = vi.fn();
    new AgentArmor({
      contentInjection: { hiddenHTML: false },
      on: { detectorSkipped: onDetectorSkipped },
    });
    expect(onDetectorSkipped).toHaveBeenCalledWith({ detectorId: 'hidden-html', reason: 'config-disabled' });
  });

  it('fires with reason "no-patterns" when the loaded pattern database lacks entries for a detector', () => {
    const onDetectorSkipped = vi.fn();
    const armor = new AgentArmor({ on: { detectorSkipped: onDetectorSkipped } });
    onDetectorSkipped.mockClear();
    armor.loadPatterns({ version: 'empty', updatedAt: new Date().toISOString(), detectors: {} });
    expect(onDetectorSkipped).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'no-patterns' })
    );
  });
});
