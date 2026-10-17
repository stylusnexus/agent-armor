import type {
  Detector,
  DetectorOptions,
  DetectorResult,
  Severity,
  Strictness,
  TextEdit,
  Threat,
  TrapCategory,
} from '../types';
import { applyEdits, mergeEdits } from '../sanitize';
import { findCredential, redactCredentialsIn, redactSecret, shannonEntropy } from './credentials';
import {
  decodeJsonString,
  findToolCallArguments,
  foldForScan,
  type ArgumentSpan,
} from './tool-call-json';
import {
  CHAIN_TARGET,
  DOWNLOADER as DOWNLOADER_SOURCE,
  RUN_AFTER_DOWNLOAD,
} from '../patterns/tool-call-sources';

export { shannonEntropy };

/**
 * Response anomaly screening (#30, Liu et al. 2026, section 7.2).
 *
 * The paper scores each returned tool call with an IsolationForest over five
 * features. This detector keeps the three that a scanner can compute from the
 * text alone and combines them by hand:
 *
 *  - shell risk: a download that is then run, secret variables or an
 *    environment dump sent out, and double, hex or percent encoding;
 *  - string entropy: Shannon entropy of long base64-like tokens;
 *  - credentials inside the arguments of a tool call.
 *
 * Every signal has a weight below 0.5, and entropy never counts by itself, so
 * one signal reports at `strict` at most. Two or more combine as
 * `1 - (1 - a)(1 - b)...`, with a small bonus when they sit inside the
 * arguments of a tool call. Documentation that mentions one of these things
 * stays under the balanced threshold.
 */

const THRESHOLD: Record<Strictness, number> = { strict: 0.3, balanced: 0.5, permissive: 0.7 };

/** Entropy (bits per character) below which a token reads as ordinary text, and above which as encoded data. */
export const ENTROPY_BENIGN = 4.5;
export const ENTROPY_ENCODED = 5.5;
/** Tokens shorter than this cannot reach the encoded range, so they are not measured. */
const ENTROPY_MIN_LENGTH = 40;
const ENTROPY_MAX_WEIGHT = 0.35;
/** The most one signal may weigh. Keeps a single signal under the balanced threshold. */
const MAX_SINGLE_WEIGHT = 0.45;
const TOOL_CALL_BONUS = 0.1;
const MAX_CONFIDENCE = 0.95;

const REPLACEMENT =
  '[BLOCKED: anomalous command flagged by AgentArmor; verify the tool call before executing]';

interface Span {
  start: number;
  end: number;
}

interface Signal extends Span {
  name: string;
  weight: number;
  /** The span holds a credential: redact it in evidence. */
  secret?: boolean;
  /** Counts toward the weight but cannot make a finding by itself. */
  supporting?: boolean;
}

// ---------------------------------------------------------------------------
// Tool-call arguments
// ---------------------------------------------------------------------------

function mergeSpans(spans: ArgumentSpan[]): ArgumentSpan[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const merged: ArgumentSpan[] = [];
  for (const s of sorted) {
    const last = merged[merged.length - 1];
    if (last && s.start < last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ ...s });
  }
  return merged;
}

interface Unit extends Span {
  inToolCall: boolean;
  /** The text to score. Arguments sent as a JSON string are decoded once, so they read like an object. */
  text: string;
}

/**
 * What gets scored: each tool call's argument span, and every other logical
 * line (a backslash at the end of a line continues it).
 */
function unitsOf(content: string, args: ArgumentSpan[]): Unit[] {
  const covered = mergeSpans(args);
  const units: Unit[] = covered.map((s) => {
    const raw = content.slice(s.start, s.end);
    return {
      start: s.start,
      end: s.end,
      inToolCall: true,
      text: s.stringified ? decodeJsonString(raw).text : raw,
    };
  });
  const n = content.length;
  let spanIndex = 0;
  let start = 0;
  while (start <= n) {
    let end = content.indexOf('\n', start);
    if (end < 0) end = n;
    while (end < n && end > start && content.charCodeAt(end - 1) === 92) {
      const next = content.indexOf('\n', end + 1);
      end = next < 0 ? n : next;
    }
    while (spanIndex < covered.length && covered[spanIndex].end <= start) spanIndex++;
    const overlaps = spanIndex < covered.length && covered[spanIndex].start < end;
    if (!overlaps && end > start) {
      units.push({ start, end, inToolCall: false, text: content.slice(start, end) });
    }
    start = end + 1;
  }
  return units;
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

/** A word that fetches from the network. */
const DOWNLOADER = new RegExp(DOWNLOADER_SOURCE, 'i');
/**
 * After a download: a pipe or chain into something that runs (the same targets
 * the tool-call patterns use), or a line break and then something that runs.
 * A line break is followed by spaces and tabs only, so a run of line breaks is
 * not rescanned from each one.
 */
const RUN_AFTER = new RegExp(`${RUN_AFTER_DOWNLOAD}|(?:\\n|\\\\{1,2}n)[ \\t]*${CHAIN_TARGET}`, 'i');

const SECRET_VAR =
  /\$\{?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|COOKIE|AUTH)[A-Z0-9_]*/;
const SUBSHELL_OR_SECRET =
  /\$\(|\)|\$\{?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|COOKIE|AUTH)[A-Z0-9_]*/g;
const URL_TOKEN = /https?:\/\/[^\s'"]+/gi;
const DATA_FLAG_VALUE = /(?:^|\s)(?:-d|--data[\w-]*|-F|--form|--upload-file|-T|--json)\s+(\S+)/g;
const ENV_DUMP = /\$\(\s*(?:env|printenv|set)\b|\bprintenv\b|\benv\s*\|\s*(?:base64|curl|nc)\b/i;
const SECRET_FILE_DUMP =
  /\$\(\s*cat\s+\S*(?:\.env\b|credentials|id_rsa|id_ed25519|\.aws\/|\.ssh\/|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\/etc\/shadow)/i;
const HEADER = /(?:-H|--header)\s+\\*["']?([A-Za-z0-9-]+):([^"'\\\n]*)/g;
const SECRET_FILE_REF =
  /@\S*(?:\.aws\/credentials|id_rsa|id_ed25519|\.ssh\/|\.env\b|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\/etc\/shadow|\.docker\/config)/i;
const SINK = /\b(?:curl|wget|nc|ncat|netcat|socat)\b|https?:\/\//i;

const BASE64_DECODE = /\bbase64\s+(?:-d|-D|--decode)\b/gi;
const B64DECODE_CALL = /\bb64decode\s*\(/gi;
const HEX_ESCAPES = /(?:\\{1,2}x[0-9a-fA-F]{2}){8,}/;
const PERCENT_RUN = /(?:%[0-9A-Fa-f]{2}){12,}/g;
const DOUBLE_PERCENT = /(?:%25[0-9A-Fa-f]{2}){3,}/;
const SHELL_WORDS = /\b(?:curl|wget|bash|sh|base64|eval|chmod|nc|python3?|exec)\b|\/bin\//i;

const TOKEN = /[A-Za-z0-9+/_-]{40,}={0,2}/g;
const JWT_NEIGHBOUR = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/;

const CHAIN_WEIGHT = 0.35;
const ENV_VAR_WEIGHT = 0.3;
const ENV_DUMP_WEIGHT = 0.45;
const DOUBLE_DECODE_WEIGHT = 0.4;
const HEX_WEIGHT = 0.35;
const PERCENT_WEIGHT = 0.4;
const DOUBLE_PERCENT_WEIGHT = 0.35;
const CREDENTIAL_WEIGHT = 0.35;

function signalsIn(text: string, base: number, inToolCall: boolean): Signal[] {
  const out: Signal[] = [];
  const add = (name: string, weight: number, start: number, end: number, extra?: Partial<Signal>) =>
    out.push({ name, weight, start: base + start, end: base + end, ...extra });

  // A download that is then run.
  // Only inside a tool call: install guides write the same line as plain text.
  const download = inToolCall ? DOWNLOADER.exec(text) : null;
  if (download) {
    const rest = text.slice(download.index + download[0].length);
    const run = RUN_AFTER.exec(rest);
    if (run) {
      const from = download.index;
      const to = download.index + download[0].length + run.index + run[0].length;
      add('a download that is run', CHAIN_WEIGHT, from, to);
    }
  }

  // Secrets sent out: a secret variable in a URL or a request body, or a dump
  // of the environment or a key file, next to something that sends data.
  if (SINK.test(text)) {
    let envFrom = -1;
    let envTo = -1;
    let weight = 0;
    const take = (w: number, s: number, e: number) => {
      if (w > weight) weight = w;
      if (envFrom < 0 || s < envFrom) envFrom = s;
      if (e > envTo) envTo = e;
    };
    const dump = ENV_DUMP.exec(text) ?? SECRET_FILE_DUMP.exec(text);
    if (dump) take(ENV_DUMP_WEIGHT, dump.index, dump.index + dump[0].length);
    for (const m of text.matchAll(URL_TOKEN)) {
      const v = SECRET_VAR.exec(m[0]);
      if (v) take(ENV_VAR_WEIGHT, m.index + v.index, m.index + v.index + v[0].length);
    }
    // A secret variable inside a command substitution: $(echo $API_KEY | base64).
    let depth = 0;
    for (const m of text.matchAll(SUBSHELL_OR_SECRET)) {
      if (m[0] === '$(') depth++;
      else if (m[0] === ')') depth = Math.max(0, depth - 1);
      else if (depth > 0) take(ENV_VAR_WEIGHT, m.index, m.index + m[0].length);
    }
    const fileRef = SECRET_FILE_REF.exec(text);
    if (fileRef) take(ENV_DUMP_WEIGHT, fileRef.index, fileRef.index + fileRef[0].length);
    // A secret variable in a header other than the one that authenticates.
    if (inToolCall) {
      for (const m of text.matchAll(HEADER)) {
        if (/^(?:proxy-)?authorization$/i.test(m[1])) continue;
        const v = SECRET_VAR.exec(m[2]);
        if (v) {
          const at = m.index + m[0].length - m[2].length + v.index;
          take(ENV_VAR_WEIGHT, at, at + v[0].length);
        }
      }
    }
    for (const m of text.matchAll(DATA_FLAG_VALUE)) {
      const v = SECRET_VAR.exec(m[1]);
      if (v) {
        const at = m.index + m[0].length - m[1].length + v.index;
        take(ENV_VAR_WEIGHT, at, at + v[0].length);
      }
    }
    if (weight > 0) add('secrets sent out through a command', weight, envFrom, envTo);
  }

  // Encoding that hides a command.
  let decodes = 0;
  let firstDecode = -1;
  let lastDecode = -1;
  for (const re of [BASE64_DECODE, B64DECODE_CALL]) {
    re.lastIndex = 0;
    let count = 0;
    let m: RegExpExecArray | null;
    let first = -1;
    let last = -1;
    while ((m = re.exec(text)) !== null) {
      count++;
      if (first < 0) first = m.index;
      last = m.index + m[0].length;
    }
    if (count > decodes) {
      decodes = count;
      firstDecode = first;
      lastDecode = last;
    }
  }
  if (decodes >= 2) add('base64 decoded twice', DOUBLE_DECODE_WEIGHT, firstDecode, lastDecode);

  const hex = HEX_ESCAPES.exec(text);
  if (hex) add('hex-escaped bytes', HEX_WEIGHT, hex.index, hex.index + hex[0].length);

  PERCENT_RUN.lastIndex = 0;
  let pct: RegExpExecArray | null;
  while ((pct = PERCENT_RUN.exec(text)) !== null) {
    let decoded = '';
    try {
      decoded = decodeURIComponent(pct[0].slice(0, 4096));
    } catch {
      continue;
    }
    if (SHELL_WORDS.test(decoded)) {
      add('a percent-encoded command', PERCENT_WEIGHT, pct.index, pct.index + pct[0].length);
      break;
    }
  }
  const doublePct = DOUBLE_PERCENT.exec(text);
  if (doublePct) {
    add(
      'double percent encoding',
      DOUBLE_PERCENT_WEIGHT,
      doublePct.index,
      doublePct.index + doublePct[0].length,
    );
  }

  // Credentials inside the arguments of a tool call.
  if (inToolCall) {
    const found = findCredential(text);
    if (found) {
      add(
        'a credential in tool call arguments',
        CREDENTIAL_WEIGHT,
        found.index,
        found.index + found.length,
        { secret: true },
      );
    }
  }

  // High-entropy tokens. Supporting only: they raise a finding another signal
  // started, never start one.
  if (out.length > 0) {
    const jwtLine = JWT_NEIGHBOUR.test(text);
    let best: { weight: number; start: number; end: number } | null = null;
    TOKEN.lastIndex = 0;
    let t: RegExpExecArray | null;
    while ((t = TOKEN.exec(text)) !== null) {
      const token = t[0];
      if (token.length < ENTROPY_MIN_LENGTH) continue;
      if (jwtLine && (text[t.index - 1] === '.' || text[t.index + token.length] === '.')) continue;
      if (/^[0-9a-fA-F]+$/.test(token)) continue;
      // A credential is high-entropy by nature; it is already a signal.
      const at = base + t.index;
      if (out.some((s) => s.secret && s.start < at + token.length && at < s.end)) continue;
      const h = shannonEntropy(token);
      const weight =
        Math.min(Math.max((h - ENTROPY_BENIGN) / (ENTROPY_ENCODED - ENTROPY_BENIGN), 0), 1) *
        ENTROPY_MAX_WEIGHT;
      if (weight > 0 && (!best || weight > best.weight)) {
        best = { weight, start: t.index, end: t.index + token.length };
      }
    }
    if (best) add('a high-entropy string', best.weight, best.start, best.end, { supporting: true });
  }

  return out;
}

function combine(signals: Signal[], inToolCall: boolean): number {
  let miss = 1;
  for (const s of signals) miss *= 1 - Math.min(s.weight, MAX_SINGLE_WEIGHT);
  let confidence = 1 - miss;
  if (inToolCall && signals.length >= 2) confidence += TOOL_CALL_BONUS;
  return Math.min(confidence, MAX_CONFIDENCE);
}

function severityFor(confidence: number): Severity {
  if (confidence >= 0.8) return 'critical';
  if (confidence >= 0.5) return 'high';
  return 'medium';
}

export class ResponseAnomalyDetector implements Detector {
  readonly id = 'response-anomaly';
  readonly name = 'Response Anomaly Detector';
  readonly category: TrapCategory = 'transport-integrity';

  scan(content: string, options?: DetectorOptions): DetectorResult {
    const threshold = THRESHOLD[options?.strictness ?? 'balanced'];
    const threats: Threat[] = [];
    const units = unitsOf(content, findToolCallArguments(content));
    for (const unit of units) {
      // The reader saw the original text; the signals read a folded copy.
      const folded = foldForScan(unit.text);
      const signals = signalsIn(folded.text, 0, unit.inToolCall);
      if (!signals.some((s) => !s.supporting)) continue;
      const confidence = combine(signals, unit.inToolCall);
      if (confidence < threshold) continue;
      const start = Math.min(...signals.map((s) => s.start));
      const end = Math.max(...signals.map((s) => s.end));
      threats.push({
        category: this.category,
        type: 'response-anomaly',
        severity: severityFor(confidence),
        confidence: Math.round(confidence * 100) / 100,
        description: `Response anomaly: ${signals.map((s) => s.name).join(', ')}`,
        evidence: this.evidence(folded.text, start, end, signals),
        // A tool call is replaced whole, so the JSON around it stays valid.
        location: unit.inToolCall
          ? { offset: unit.start, length: unit.end - unit.start }
          : (() => {
              const at = folded.back(start, end - start);
              return { offset: unit.start + at.offset, length: at.length };
            })(),
        detectorId: this.id,
        source: 'pattern',
      });
    }
    return { threats };
  }

  sanitizeEdits(content: string, threats: Threat[]): TextEdit[] {
    return threats
      .filter((t) => t.location)
      .map((t) => {
        const { offset, length } = t.location!;
        // Arguments are an object, or the inside of a JSON string (an object sent
        // as a string). Each gets a replacement that is valid where it sits.
        const startsObject = content[offset] === '{' && content[offset + length - 1] === '}';
        const inString = content[offset - 1] === '"';
        const replacement =
          startsObject && inString
            ? `{\\"blocked\\":\\"${REPLACEMENT}\\"}`
            : startsObject
              ? `{"blocked":"${REPLACEMENT}"}`
              : REPLACEMENT;
        // An object edit is critical so that, where it overlaps a narrower edit
        // inside it, the object stays valid.
        return {
          offset,
          length,
          replacement,
          severity: startsObject ? ('critical' as const) : t.severity,
        };
      });
  }

  sanitize(content: string, threats: Threat[]): string {
    return applyEdits(content, mergeEdits(this.sanitizeEdits(content, threats), content.length));
  }

  /** The flagged text, with any credential cut down to a format-identifying prefix. */
  private evidence(content: string, start: number, end: number, signals: Signal[]): string {
    let out = '';
    let at = start;
    for (const s of signals.filter((x) => x.secret).sort((a, b) => a.start - b.start)) {
      if (s.start < at) continue;
      out += content.slice(at, s.start) + redactSecret(content.slice(s.start, s.end));
      at = s.end;
    }
    out = redactCredentialsIn(out + content.slice(at, end));
    return out.length > 200 ? out.slice(0, 197) + '...' : out;
  }
}
