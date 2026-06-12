/**
 * Unicode normalization for scan inputs.
 *
 * Pattern detectors match raw strings, so an attacker can slip past them with
 * visually identical characters (Cyrillic/Greek look-alikes, fullwidth forms,
 * mathematical alphanumerics) or by sprinkling invisible characters between
 * letters. This module produces a normalized "skeleton" of the input that
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
  "а": "a", // а
  "е": "e", // е
  "о": "o", // о
  "р": "p", // р
  "с": "c", // с
  "у": "y", // у
  "х": "x", // х
  "і": "i", // і
  "ј": "j", // ј
  "ѕ": "s", // ѕ
  "һ": "h", // һ
  "ԁ": "d", // ԁ
  "ԛ": "q", // ԛ
  "ɡ": "g", // ɡ (Latin small script g)
  // ── Cyrillic (uppercase) ──
  "А": "A", // А
  "В": "B", // В
  "Е": "E", // Е
  "К": "K", // К
  "М": "M", // М
  "Н": "H", // Н
  "О": "O", // О
  "Р": "P", // Р
  "С": "C", // С
  "Т": "T", // Т
  "У": "Y", // У
  "Х": "X", // Х
  "І": "I", // І
  "Ѕ": "S", // Ѕ
  "Ј": "J", // Ј
  // ── Greek (lowercase) ──
  "α": "a", // α
  "ο": "o", // ο
  "ε": "e", // ε
  "ρ": "p", // ρ
  "ν": "v", // ν
  "ι": "i", // ι
  "κ": "k", // κ
  "χ": "x", // χ
  // ── Greek (uppercase) ──
  "Α": "A", // Α
  "Β": "B", // Β
  "Ε": "E", // Ε
  "Ζ": "Z", // Ζ
  "Η": "H", // Η
  "Ι": "I", // Ι
  "Κ": "K", // Κ
  "Μ": "M", // Μ
  "Ν": "N", // Ν
  "Ο": "O", // Ο
  "Ρ": "P", // Ρ
  "Τ": "T", // Τ
  "Υ": "Y", // Υ
  "Χ": "X", // Χ
};

/** Codepoints stripped entirely: zero-width, bidi controls, joiners, VS, soft hyphen. */
const STRIP = new Set<string>([
  "­", // soft hyphen
  "᠎", // Mongolian vowel separator
  "​", // zero-width space
  "‌", // zero-width non-joiner
  "‍", // zero-width joiner
  "‎", // LTR mark
  "‏", // RTL mark
  "⁠", // word joiner
  "⁡", // function application
  "⁢", // invisible times
  "⁣", // invisible separator
  "⁤", // invisible plus
  "‪", // LRE
  "‫", // RLE
  "‬", // PDF
  "‭", // LRO
  "‮", // RLO
  "⁦", // LRI
  "⁧", // RLI
  "⁨", // FSI
  "⁩", // PDI
  "﻿", // BOM / zero-width no-break space
]);

const isVariationSelector = (cp: number): boolean =>
  (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0xe0100 && cp <= 0xe01ef);

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
  let srcIdx = 0;

  for (const ch of content) {
    const cp = ch.codePointAt(0) ?? 0;

    // ASCII passes straight through (NFKC is identity for it).
    if (cp < 0x80) {
      map.push(srcIdx);
      out.push(ch);
      srcIdx += 1;
      continue;
    }

    const unitLen = ch.length; // 1 or 2 UTF-16 units

    if (STRIP.has(ch) || isVariationSelector(cp)) {
      srcIdx += unitLen;
      continue;
    }

    const folded = ch.normalize("NFKC");
    for (const c of folded) {
      const skeleton = CONFUSABLES[c] ?? c;
      for (let k = 0; k < skeleton.length; k++) {
        map.push(srcIdx);
      }
      out.push(skeleton);
    }
    srcIdx += unitLen;
  }

  const normalized = out.join("");
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
  length: number
): { offset: number; length: number } {
  if (norm.map.length === 0) {
    return { offset: 0, length: 0 };
  }
  const startIdx = Math.min(offset, norm.map.length - 1);
  const origStart = norm.map[startIdx];
  const endUnit = offset + length;
  const origEnd =
    endUnit < norm.map.length ? norm.map[endUnit] : norm.originalLength;
  return { offset: origStart, length: Math.max(0, origEnd - origStart) };
}
