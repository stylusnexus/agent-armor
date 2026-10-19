/**
 * Example: Express middleware that scans incoming content for agent traps
 *
 * Install: npm install express @stylusnexus/agentarmor
 * Run: npx tsx examples/express-middleware.ts
 */

// import express from 'express';
import { AgentArmor } from '@stylusnexus/agentarmor';

const armor = AgentArmor.regexOnly({ strictness: 'balanced' });

/**
 * Express middleware that scans request body for agent traps.
 * Attach to routes where user content flows into AI agent context.
 */
export function agentArmorMiddleware(fieldName: string = 'content') {
  return (req: any, res: any, next: any) => {
    const value = req.body?.[fieldName];
    const isArray = Array.isArray(value);
    if (
      (isArray && (value.length === 0 || value.some((item: unknown) => typeof item !== 'string'))) ||
      (!isArray && typeof value !== 'string')
    ) {
      return res.status(400).json({
        error: 'Content must be a string or a non-empty array of strings',
      });
    }
    const contents: string[] = isArray ? value : [value];

    // Scan every direct string member. Unsupported array shapes are rejected
    // above so no unscanned object or nested value reaches downstream code.
    const results = contents.map((content) => armor.scanSync(content));

    // Hard-block the most dangerous content using the single risk roll-up,
    // instead of iterating threats to make the same decision by hand.
    if (results.some((result) => result.riskLevel === 'critical' || result.riskLevel === 'high')) {
      const riskLevel = results.some((result) => result.riskLevel === 'critical')
        ? 'critical'
        : 'high';
      return res.status(422).json({
        error: 'Content blocked by security scan',
        riskLevel,
      });
    }

    for (const result of results) {
      if (result.clean) continue;

      // Log the threats for monitoring
      console.warn('[AgentArmor]', {
        path: req.path,
        riskLevel: result.riskLevel,
        threats: result.threats.map((t) => ({
          type: t.type,
          severity: t.severity,
          confidence: t.confidence,
          source: t.source,
        })),
      });
    }

    // Lower-risk threats: sanitize strings and continue (recommended).
    if (isArray) {
      let resultIndex = 0;
      req.body[fieldName] = value.map((item: unknown) =>
        typeof item === 'string' ? results[resultIndex++].sanitized : item,
      );
      // Arrays can contain multiple independent scan results.
      req.agentArmorResult = results;
    } else {
      req.body[fieldName] = results[0].sanitized;
      // Keep the existing scalar contract for downstream handlers.
      req.agentArmorResult = results[0];
    }

    next();
  };
}

// Usage with Express:
// const app = express();
// app.use(express.json());
// app.post('/api/chat', agentArmorMiddleware('message'), (req, res) => {
//   // req.body.message is now sanitized
//   // req.agentArmorResult has the ScanResult (or ScanResult[] for an array)
//   res.json({ reply: 'Processing your safe message...' });
// });

// Demo without Express:
function runDemo() {
  const mockReq = {
    path: '/api/chat',
    body: {
      message: [
        'Please summarize the next paragraph.',
        'Hello, please summarize the next paragraph.',
      ],
    },
  };
  const mockRes = {
    status: (status: number) => ({ json: () => console.log('  Blocked with status:', status) }),
  };
  let nextCalled = false;

  agentArmorMiddleware('message')(mockReq, mockRes, () => {
    nextCalled = true;
  });

  console.log('Middleware demo:');
  console.log('  String entries scanned:', (mockReq as any).agentArmorResult?.length ?? 0);
  console.log('  Sanitized entries:', JSON.stringify(mockReq.body.message));
  console.log('  Next called:', nextCalled);
  console.log(
    '  Threats found:',
    ((mockReq as any).agentArmorResult ?? []).reduce(
      (total: number, result: { threats: unknown[] }) => total + result.threats.length,
      0,
    ),
  );
}

// Keep importing the middleware safe for applications that copy or reuse it.
if (process.argv[1]?.endsWith('express-middleware.ts')) runDemo();
