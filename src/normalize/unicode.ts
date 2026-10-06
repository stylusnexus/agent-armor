/**
 * Unicode normalization for scan inputs.
 *
 * Pattern detectors match raw strings, so an attacker can slip past them with
 * visually identical characters (Cyrillic/Greek look-alikes, fullwidth forms,
 * mathematical alphanumerics) or by sprinkling invisible characters between
 * letters. This module produces a normalized 'skeleton' of the input that
 * semantic detectors scan instead, while keeping an offset map back to the
 * original so evidence and sanitization still operate on the real bytes.
 *
 * Two transforms are applied, per Unicode codepoint:
 *   1. NFKC compatibility normalization (folds fullwidth, ligatures, and the
 *      mathematical alphanumeric ranges down to ASCII).
 *   2. Confusable folding — a curated cross-script look-alike table that NFKC
 *      does NOT cover (it keeps Cyrillic/Greek distinct from Latin).
 * Invisible / formatting characters (zero-width, bidi controls, variation
 * selectors, soft hyphen) are dropped.
 *
 * NOTE: structural detectors (hidden-html, syntactic-masking) deliberately run
 * on the RAW input — they exist to catch the very characters this pass removes.
 */

/**
 * Cross-script confusables → ASCII skeleton. NFKC handles fullwidth and the
 * math alphanumerics, so this table only carries look-alikes NFKC leaves alone.
 * Curated subset of Unicode TR39; the full confusables DB is a follow-up.
 */
const CONFUSABLES: Record<string, string> = {
  // ── Cyrillic (lowercase) ──
  а: 'a', // а
  е: 'e', // е
  о: 'o', // о
  р: 'p', // р
  с: 'c', // с
  у: 'y', // у
  х: 'x', // х
  і: 'i', // і
  ј: 'j', // ј
  ѕ: 's', // ѕ
  һ: 'h', // һ
  ԁ: 'd', // ԁ
  ԛ: 'q', // ԛ
  ɡ: 'g', // ɡ (Latin small script g)
  // ── Cyrillic (uppercase) ──
  А: 'A', // А
  В: 'B', // В
  Е: 'E', // Е
  К: 'K', // К
  М: 'M', // М
  Н: 'H', // Н
  О: 'O', // О
  Р: 'P', // Р
  С: 'C', // С
  Т: 'T', // Т
  У: 'Y', // У
  Х: 'X', // Х
  І: 'I', // І
  Ѕ: 'S', // Ѕ
  Ј: 'J', // Ј
  // ── Greek (lowercase) ──
  α: 'a', // α
  ο: 'o', // ο
  ε: 'e', // ε
  ρ: 'p', // ρ
  ν: 'v', // ν
  ι: 'i', // ι
  κ: 'k', // κ
  χ: 'x', // χ
  // ── Greek (uppercase) ──
  Α: 'A', // Α
  Β: 'B', // Β
  Ε: 'E', // Ε
  Ζ: 'Z', // Ζ
  Η: 'H', // Η
  Ι: 'I', // Ι
  Κ: 'K', // Κ
  Μ: 'M', // Μ
  Ν: 'N', // Ν
  Ο: 'O', // Ο
  Ρ: 'P', // Ρ
  Τ: 'T', // Τ
  Υ: 'Y', // Υ
  Χ: 'X', // Χ
};

/** Codepoints stripped entirely: zero-width, bidi controls, joiners, VS, soft hyphen. */
const STRIP = new Set<string>([
  '­', // soft hyphen
  '᠎', // Mongolian vowel separator
  '​', // zero-width space
  '‌', // zero-width non-joiner
  '‍', // zero-width joiner
  '‎', // LTR mark
  '‏', // RTL mark
  '⁠', // word joiner
  '⁡', // function application
  '⁢', // invisible times
  '⁣', // invisible separator
  '⁤', // invisible plus
  '‪', // LRE
  '‫', // RLE
  '‬', // PDF
  '‭', // LRO
  '‮', // RLO
  '⁦', // LRI
  '⁧', // RLI
  '⁨', // FSI
  '⁩', // PDI
  '﻿', // BOM / zero-width no-break space
]);

const isVariationSelector = (cp: number): boolean =>
  (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

/** Arabic tatweel (a stretching character) and the optional vowel marks: decoration that a reader skips. */
const isArabicDecoration = (cp: number): boolean =>
  cp === 0x0640 || (cp >= 0x064b && cp <= 0x065f) || cp === 0x0670;

/** Dropped without trace: invisible and formatting characters, variation selectors, Arabic decoration. */
const isDropped = (cp: number, ch: string): boolean =>
  STRIP.has(ch) || isVariationSelector(cp) || isArabicDecoration(cp);

/**
 * Bumped when the skeleton changes what it produces, so data written against an older skeleton (language packs
 * hold literals in skeleton form) can be rejected instead of silently failing to match.
 */
export const NORMALIZER_VERSION = 2;

/** NFKC composes only inside a group of this many marks or fewer (Unicode's stream-safe limit is 30). */
const MAX_CLUSTER_MARKS = 30;

/** Whether a mark can follow the code unit `u`: below U+0300 nothing attaches, except the soft hyphen, which is dropped. */
const canTakeFastPath = (u: number): boolean => u < 0x300 && u !== 0xad;

/** Any space character: a mark on a non-breaking or ideographic space would otherwise survive and split a phrase. */
const SPACE = /^\p{Zs}$/u;
const COMBINING_MARK = /^\p{M}$/u;
/** A letter in a script whose accents carry no meaning for matching a phrase (unlike Indic vowel signs or kana marks). */
const ACCENTED_SCRIPT = /^[\p{Script=Latin}\p{Script=Greek}\p{Script=Cyrillic}]/u;

/**
 * Whether `cp` continues the cluster that starts at `base`: a combining mark, a halfwidth katakana voicing mark, or
 * a Hangul vowel or final jamo that composes with the one before it. NFKC only composes within such a cluster.
 */
function continuesCluster(base: number, cp: number): boolean {
  // CJK ideographs and Hangul syllables are never marks; most text in those scripts exits here.
  if ((cp >= 0x3400 && cp <= 0x9fff) || (cp >= 0xac00 && cp <= 0xd7a3)) return false;
  if (cp >= 0x300) {
    if (cp >= 0xff9e && cp <= 0xff9f) return base >= 0xff66 && base <= 0xff9d;
    if (cp >= 0x1160 && cp <= 0x11a7)
      return (
        (base >= 0x1100 && base <= 0x115f) ||
        (base >= 0x1160 && base <= 0x11a7) ||
        (base >= 0xac00 && base <= 0xd7a3)
      );
    if (cp >= 0x11a8 && cp <= 0x11ff)
      return (base >= 0x1100 && base <= 0x11ff) || (base >= 0xac00 && base <= 0xd7a3);
    return COMBINING_MARK.test(String.fromCodePoint(cp));
  }
  return false;
}

/**
 * Latin, Greek and Cyrillic: drop the accents (an accent is a way to dodge a phrase match, and a reader skips it).
 * Everything else is composed and keeps its marks.
 */
function foldCluster(cluster: string): string {
  if (ACCENTED_SCRIPT.test(cluster.normalize('NFKC'))) {
    return cluster.normalize('NFD').replace(/\p{M}/gu, '').normalize('NFKC');
  }
  return cluster.normalize('NFKC');
}

const SINGLE_CACHE = new Map<string, string>();
const SINGLE_CACHE_LIMIT = 4096;

/** `foldCluster` for one character, remembered for the common scripts; the cap bounds memory on hostile input. */
function foldOne(ch: string): string {
  const hit = SINGLE_CACHE.get(ch);
  if (hit !== undefined) return hit;
  const folded = foldCluster(ch);
  if (SINGLE_CACHE.size < SINGLE_CACHE_LIMIT) SINGLE_CACHE.set(ch, folded);
  return folded;
}

export interface NormalizedText {
  /** The folded skeleton that semantic detectors should scan. */
  normalized: string;
  /**
   * Offset map: `map[i]` is the UTF-16 index in the ORIGINAL string that
   * produced normalized unit `i`. Length equals `normalized.length`.
   */
  map: number[];
  /** Length of the original input, for end-of-range mapping. */
  originalLength: number;
  /** True if normalization changed the text (a homoglyph/invisible-char tell). */
  changed: boolean;
}

/**
 * Produce an offset-mapped normalized skeleton of `content`.
 * Iterates by codepoint so astral characters (e.g. math alphanumerics) map
 * to the correct UTF-16 offsets.
 */
export function normalizeForScan(content: string): NormalizedText {
  // Fast path: pure-ASCII content needs no normalization. The charCode scan is
  // allocation-free, so the common case stays cheap even on large inputs.
  let hasNonAscii = false;
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) >= 0x80) {
      hasNonAscii = true;
      break;
    }
  }
  if (!hasNonAscii) {
    return {
      normalized: content,
      map: [],
      originalLength: content.length,
      changed: false,
    };
  }

  const out: string[] = [];
  const map: number[] = [];
  const n = content.length;
  let i = 0; // UTF-16 index into the original

  while (i < n) {
    const cp = content.codePointAt(i) ?? 0;
    const unitLen = cp > 0xffff ? 2 : 1;

    // ASCII passes straight through unless a combining mark follows it (NFKC is identity for ASCII alone).
    if (cp < 0x80 && (i + 1 >= n || canTakeFastPath(content.charCodeAt(i + 1)))) {
      map.push(i);
      out.push(content[i]);
      i += 1;
      continue;
    }

    const ch = String.fromCodePoint(cp);
    if (isDropped(cp, ch)) {
      i += unitLen;
      continue;
    }

    // A cluster: this character plus the marks and jamo that compose with it. Invisible characters inside it are
    // dropped, so zero-width padding between a letter and its accent does not split them. Most characters have
    // nothing after them that can attach, and those take the cached path.
    let j = i + unitLen;
    let folded: string;
    if (j >= n || canTakeFastPath(content.charCodeAt(j))) {
      folded = foldOne(ch);
    } else {
      // Marks after ASCII, spaces, Latin, Greek and Cyrillic are dropped as they are read, so a long run of them costs
      // one pass. Other groups are cut at MAX_CLUSTER_MARKS (Unicode's stable-text limit), which keeps
      // normalization, whose sort is quadratic in a group, linear in the whole text.
      let accentBase: boolean | undefined;
      let cluster = ch;
      let marks = 0;
      while (j < n) {
        const next = content.codePointAt(j) ?? 0;
        const nextCh = String.fromCodePoint(next);
        const nextLen = next > 0xffff ? 2 : 1;
        if (isDropped(next, nextCh)) {
          j += nextLen;
          continue;
        }
        if (!continuesCluster(cp, next)) break;
        accentBase ??= cp < 0x80 || ACCENTED_SCRIPT.test(ch.normalize('NFKC')) || SPACE.test(ch);
        if (!accentBase) {
          if (marks >= MAX_CLUSTER_MARKS) break;
          cluster += nextCh;
          marks++;
        }
        j += nextLen;
      }
      folded = accentBase || marks === 0 ? foldOne(ch) : foldCluster(cluster);
    }

    for (const c of folded) {
      const skeleton = CONFUSABLES[c] ?? c;
      for (let k = 0; k < skeleton.length; k++) map.push(i);
      out.push(skeleton);
    }
    i = j;
  }

  const normalized = out.join('');
  return {
    normalized,
    map,
    originalLength: content.length,
    changed: normalized !== content,
  };
}

/**
 * Translate a [offset, length) range in normalized space back to the original
 * string. The end is taken from the source index of the next normalized unit
 * (or the original length), so any invisible characters dropped inside the
 * span are included in the original range.
 */
export function mapRangeToOriginal(
  norm: NormalizedText,
  offset: number,
  length: number,
): { offset: number; length: number } {
  if (norm.map.length === 0) {
    return { offset: 0, length: 0 };
  }
  const startIdx = Math.min(offset, norm.map.length - 1);
  const origStart = norm.map[startIdx];
  // End = just past the last source codepoint covered by the range. We find the
  // next surviving source index after the last covered unit, which correctly
  // spans multi-unit expansions (one source char -> several normalized units)
  // and includes any dropped characters that fell inside the span.
  const lastIdx = Math.min(offset + length - 1, norm.map.length - 1);
  const lastSrc = norm.map[lastIdx];
  let origEnd = norm.originalLength;
  for (let k = lastIdx + 1; k < norm.map.length; k++) {
    if (norm.map[k] > lastSrc) {
      origEnd = norm.map[k];
      break;
    }
  }
  return { offset: origStart, length: Math.max(0, origEnd - origStart) };
}
