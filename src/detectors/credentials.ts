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

/**
 * Credential shapes. The last one is a key name followed by a long value; its
 * capture group 1 is the value.
 */
export const CREDENTIALS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{40,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}/g,
  /["']?(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|passwd|authorization|client[_-]?secret|private[_-]?key)["']?\s*[:=]\s*\\?["']([^"'\\\s]{16,})/gi,
];

/** Bits per character below which a value is too regular to be a secret. */
export const CREDENTIAL_MIN_ENTROPY = 3.2;

/**
 * Cut every credential in `text` down to a format-identifying prefix, so
 * evidence that quotes a command does not carry the secret into a log.
 */
export function redactCredentialsIn(text: string): string {
  let out = text;
  for (const re of CREDENTIALS) {
    re.lastIndex = 0;
    out = out.replace(re, (whole: string, group?: string) => {
      const value = typeof group === 'string' ? group : whole;
      if (PLACEHOLDER.test(value) || shannonEntropy(value) < CREDENTIAL_MIN_ENTROPY) return whole;
      return typeof group === 'string'
        ? whole.replace(group, redactSecret(group))
        : redactSecret(whole);
    });
  }
  return out;
}
