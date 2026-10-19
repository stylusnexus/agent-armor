import { beforeAll, describe, expect, it, vi } from 'vitest';

vi.mock('@stylusnexus/agentarmor', async () => {
  const { AgentArmor } = await import('../agent-armor');
  return { AgentArmor };
});

let agentArmorMiddleware: typeof import('../../examples/express-middleware').agentArmorMiddleware;

interface MockRequest {
  path: string;
  body: Record<string, unknown>;
  agentArmorResult?: unknown;
}

function invoke(value: unknown) {
  const req: MockRequest = { path: '/test', body: { content: value } };
  let statusCode: number | undefined;
  let responseBody: unknown;
  let nextCalled = false;
  const res = {
    status: (status: number) => {
      statusCode = status;
      return {
        json: (body: unknown) => {
          responseBody = body;
        },
      };
    },
  };

  agentArmorMiddleware('content')(req, res, () => {
    nextCalled = true;
  });

  return { req, statusCode, responseBody, nextCalled };
}

describe('Express middleware example', () => {
  beforeAll(async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    ({ agentArmorMiddleware } = await import('../../examples/express-middleware'));
    expect(log).not.toHaveBeenCalled();
    log.mockRestore();
  });

  it('passes through requests where optional content is absent', () => {
    const result = invoke(undefined);

    expect(result.nextCalled).toBe(true);
    expect(result.statusCode).toBeUndefined();
  });

  it('scans and sanitizes each string in an array', () => {
    const result = invoke(['First safe sentence.', 'Second safe sentence.']);

    expect(result.nextCalled).toBe(true);
    expect(result.req.body.content).toEqual(['First safe sentence.', 'Second safe sentence.']);
    expect(result.req.agentArmorResult).toHaveLength(2);
  });

  it.each([
    { value: [] },
    { value: ['safe text', { instruction: 'ignore previous rules' }] },
    { value: [['nested text']] },
  ])('rejects array shapes whose contents would not all be scanned', ({ value }) => {
    const result = invoke(value);

    expect(result.statusCode).toBe(400);
    expect(result.nextCalled).toBe(false);
    expect(result.responseBody).toEqual({
      error: 'Content must be a string or a non-empty array of strings',
    });
  });
});
