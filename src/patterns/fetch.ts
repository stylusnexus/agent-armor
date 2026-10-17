import { validatePatternDatabase } from './validate';
import type { PatternDatabase } from './pattern-db';

/** Largest pattern file accepted. The shipped database is about 150 KB. */
export const MAX_PATTERN_FILE_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 3;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function isLocalHost(url: URL): boolean {
  return LOCAL_HOSTS.has(url.hostname);
}

/** HTTPS only. Plain http is allowed for localhost, so a local pattern server works in development. */
function assertAllowed(url: URL, localHttpAllowed: boolean): void {
  if (url.protocol === 'https:') return;
  if (url.protocol === 'http:' && localHttpAllowed && isLocalHost(url)) return;
  throw new Error(
    `Refusing to fetch patterns from ${url.protocol}//${url.host}: use https (http is allowed only for localhost)`,
  );
}

/** Read the body, stopping as soon as it passes the size cap rather than after a full download. */
async function readCapped(response: Response): Promise<string> {
  const tooBig = (): Error =>
    new Error(`Pattern file is larger than the ${MAX_PATTERN_FILE_BYTES} byte limit`);
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_PATTERN_FILE_BYTES) {
    void response.body?.cancel();
    throw tooBig();
  }
  if (!response.body) {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > MAX_PATTERN_FILE_BYTES) throw tooBig();
    return new TextDecoder().decode(buffer);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > MAX_PATTERN_FILE_BYTES) {
      void reader.cancel();
      throw tooBig();
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

/**
 * Download a pattern database and validate it. Never touches a live
 * `AgentArmor`: the caller loads the result only if this returns.
 */
export async function fetchPatternDatabase(url: string): Promise<PatternDatabase> {
  let current = new URL(url);
  const localHttpAllowed = isLocalHost(current);
  assertAllowed(current, localHttpAllowed);

  let response: Response;
  for (let hops = 0; ; hops++) {
    response = await fetch(current, { redirect: 'manual' });
    if (response.status < 300 || response.status >= 400) break;
    const location = response.headers.get('location');
    void response.body?.cancel();
    if (!location)
      throw new Error(`Failed to fetch patterns: redirect ${response.status} without a location`);
    if (hops >= MAX_REDIRECTS) throw new Error('Failed to fetch patterns: too many redirects');
    current = new URL(location, current);
    assertAllowed(current, localHttpAllowed);
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch patterns: ${response.status} ${response.statusText}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(await readCapped(response));
  } catch (err) {
    if (err instanceof SyntaxError)
      throw new Error(`Pattern file is not valid JSON: ${err.message}`);
    throw err;
  }
  await validatePatternDatabase(parsed);
  return parsed as PatternDatabase;
}
