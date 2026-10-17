import { DEFAULT_PATTERNS } from '../patterns/default-patterns';
import { findMatcher } from '../patterns/matchers';
import { decodeJsonString } from './tool-call-json';

/** Characters of a secret kept in redacted evidence: enough to identify the format, never enough to use it. */
const EVIDENCE_PREFIX_CHARS = 4;

/**
 * Reduce a matched secret to a non-usable fingerprint: a short format-identifying
 * prefix plus the original length. Provider key prefixes are format identifiers,
 * not secret material, so keeping four characters aids triage without carrying
 * the value.
 */
export function redactSecret(match: string): string {
  const trimmed = match.trim();
  if (trimmed.length <= EVIDENCE_PREFIX_CHARS) return '[REDACTED]';
  const prefix = trimmed.slice(0, EVIDENCE_PREFIX_CHARS);
  return `${prefix}[REDACTED ${trimmed.length} chars]`;
}

/** Shannon entropy of `text`, in bits per character. Characters outside ASCII are counted as one bucket. */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Int32Array(129);
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    counts[c < 128 ? c : 128]++;
  }
  let h = 0;
  for (let i = 0; i < counts.length; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / text.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Text that marks a value as an example, not a secret. */
export const PLACEHOLDER =
  /EXAMPLE|example|xxxx|XXXX|your|YOUR|placeholder|redacted|REDACTED|<[^>]*>|\*{4}|\.{3}/;

/** Bits per character below which a value is too regular to be a secret. */
export const CREDENTIAL_MIN_ENTROPY = 3.2;

/**
 * A credential shape. `group` is the capture group that holds the secret (the
 * whole match when absent). `anyLength` skips the entropy check: a password
 * after `-u user:` or in `https://user:pw@host` can be short and plain.
 */
interface CredentialShape {
  re: RegExp;
  group?: number;
  anyLength?: boolean;
}

/**
 * Credential shapes beyond the ones credential-exposure (#28) reports. All are
 * linear: each starts at a literal or a word boundary and reads one token.
 */
const EXTRA_SHAPES: CredentialShape[] = [
  { re: /\bhf_[A-Za-z0-9]{30,}/g },
  { re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}/g },
  { re: /\bhooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g },
  { re: /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g },
  { re: /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}/g },
  { re: /(?:^|\s)(?:-u|--user)\s+\\*["']?[^\s:"'\\]+:([^\s"'\\]{3,})/g, group: 1, anyLength: true },
  { re: /:\/\/[^\s/:@"'\\]+:([^\s/@"'\\]{3,})@/g, group: 1, anyLength: true },
  {
    re: /\b[A-Za-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_]*["']?\s*[:=]\s*\\?["']?(?![$<{])([^"'\\\s]{16,})/gi,
    group: 1,
  },
];

/** The shapes credential-exposure uses, compiled once, with the matcher it ships where it has one. */
const CREDENTIAL_EXPOSURE = (DEFAULT_PATTERNS.detectors['credential-exposure'] ?? []).map((e) => ({
  regex: new RegExp(e.regex, e.flags.includes('g') ? e.flags : e.flags + 'g'),
  matcher: findMatcher(e.regex, e.flags, e.extractGroup ?? 0),
  group: e.extractGroup ?? 0,
}));

/** Evidence is cut to this many characters before it is redacted, so a secret that straddles the cut is whole when it is redacted. */
const REDACT_WINDOW = 2000;

function isSecret(value: string, shape: CredentialShape): boolean {
  if (PLACEHOLDER.test(value)) return false;
  return shape.anyLength === true || shannonEntropy(value) >= CREDENTIAL_MIN_ENTROPY;
}

/**
 * Cut every credential in `text` down to a format-identifying prefix, so
 * evidence that quotes a command does not carry the secret into a log. JSON
 * escapes are decoded first (`ghp\u005f...` is still a token), and only the
 * first 2,000 characters are kept, which is far more than evidence shows.
 */
export function redactCredentialsIn(text: string): string {
  let out = text.length > REDACT_WINDOW ? text.slice(0, REDACT_WINDOW) : text;
  if (out.includes('\\')) out = decodeJsonString(out).text;

  for (const c of CREDENTIAL_EXPOSURE) {
    const shape: CredentialShape = { re: c.regex, group: c.group || undefined };
    if (c.matcher) {
      const hits = c.matcher.match(out);
      let result = '';
      let at = 0;
      for (const hit of hits) {
        const value = hit.extracted ?? hit.text;
        result += out.slice(at, hit.index);
        result +=
          value && isSecretLike(value, shape)
            ? hit.text.replace(value, redactSecret(value))
            : hit.text;
        at = hit.index + hit.text.length;
      }
      out = result + out.slice(at);
    } else {
      out = replaceIn(out, shape);
    }
  }
  for (const shape of EXTRA_SHAPES) out = replaceIn(out, shape);
  return out;
}

const isSecretLike = (value: string, shape: CredentialShape) => isSecret(value, shape);

function replaceIn(text: string, shape: CredentialShape): string {
  shape.re.lastIndex = 0;
  return text.replace(shape.re, (...args: unknown[]) => {
    const whole = args[0] as string;
    const value = shape.group ? (args[shape.group] as string | undefined) : whole;
    if (!value || !isSecret(value, shape)) return whole;
    return shape.group ? whole.replace(value, redactSecret(value)) : redactSecret(whole);
  });
}

/** Where credential-exposure's shape `c` matches in `text`, with the secret it found. */
function exposureHits(c: (typeof CREDENTIAL_EXPOSURE)[number], text: string) {
  if (c.matcher) {
    return c.matcher
      .match(text)
      .map((h) => ({ index: h.index, length: h.text.length, value: h.extracted ?? h.text }));
  }
  const hits: Array<{ index: number; length: number; value: string }> = [];
  c.regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = c.regex.exec(text)) !== null) {
    hits.push({ index: m.index, length: m[0].length, value: (c.group ? m[c.group] : m[0]) ?? '' });
    if (m[0].length === 0) c.regex.lastIndex++;
  }
  return hits;
}

/**
 * The first credential in `text`: a shape credential-exposure reports (using
 * its linear matcher where it has one), or one of the extras above.
 */
export function findCredential(text: string): { index: number; length: number } | null {
  for (const c of CREDENTIAL_EXPOSURE) {
    const shape: CredentialShape = { re: c.regex, group: c.group || undefined };
    for (const hit of exposureHits(c, text)) {
      if (hit.value && isSecret(hit.value, shape)) return { index: hit.index, length: hit.length };
    }
  }
  for (const shape of EXTRA_SHAPES) {
    shape.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = shape.re.exec(text)) !== null) {
      const value = shape.group ? m[shape.group] : m[0];
      if (value && isSecret(value, shape)) return { index: m.index, length: m[0].length };
      if (m[0].length === 0) shape.re.lastIndex++;
    }
  }
  return null;
}
