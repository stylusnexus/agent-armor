import type { Severity, TextEdit, Threat } from './types';

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/** A replacement marker beats a bare removal, so a block is never silent; then higher severity. */
function outranks(candidate: TextEdit, holder: TextEdit): boolean {
  const candidateMarks = candidate.replacement !== '';
  const holderMarks = holder.replacement !== '';
  if (candidateMarks !== holderMarks) return candidateMarks;
  return RANK[candidate.severity] > RANK[holder.severity];
}

/**
 * Merge edits that overlap into one, so a stretch of text is edited once.
 *
 * Every edit's offset is measured on the same original text. Edits that
 * overlap (an offset inside the previous edit's span) become one edit over
 * the union of their spans, and it keeps one replacement: a marker rather than
 * a bare removal, then the higher severity, then the one that came first
 * (earlier start, then longer, then earlier in input order). Edits that only
 * touch stay
 * separate. Edits outside the text are dropped; one that runs past the end is
 * cut at the end.
 */
export function mergeEdits(edits: TextEdit[], contentLength: number): TextEdit[] {
  const sorted = edits
    .filter((e) => e.offset >= 0 && e.offset <= contentLength && e.length >= 0)
    .map((e) => ({ ...e, length: Math.min(e.length, contentLength - e.offset) }))
    .sort((a, b) => a.offset - b.offset || b.length - a.length);

  const merged: TextEdit[] = [];
  let current: TextEdit | undefined;
  for (const edit of sorted) {
    if (current && edit.offset < current.offset + current.length) {
      const end = Math.max(current.offset + current.length, edit.offset + edit.length);
      const winner = outranks(edit, current) ? edit : current;
      current = {
        offset: current.offset,
        length: end - current.offset,
        replacement: winner.replacement,
        severity: winner.severity,
      };
    } else {
      if (current) merged.push(current);
      current = edit;
    }
  }
  if (current) merged.push(current);
  return merged;
}

/** Apply non-overlapping edits (from {@link mergeEdits}) to the text they were measured on. */
export function applyEdits(content: string, edits: TextEdit[]): string {
  if (edits.length === 0) return content;
  const parts: string[] = [];
  let at = 0;
  for (const edit of edits) {
    parts.push(content.slice(at, edit.offset), edit.replacement);
    at = edit.offset + edit.length;
  }
  parts.push(content.slice(at));
  return parts.join('');
}

/**
 * Edits for a detector that only returns cleaned text. Each threat span (or run
 * of touching spans) is one edit; what the detector put there is found by
 * locating the unchanged text between spans in its output. One edit spanning
 * from the first change to the last would carry the unchanged text between
 * findings along with it, and could put back text another detector flagged.
 * Returns null when the output does not fit that shape (the detector edited
 * outside its own findings); the caller then runs that detector on the merged result.
 */
export function alignedEdits(
  original: string,
  sanitized: string,
  threats: Threat[],
): TextEdit[] | null {
  const spans = threats
    .filter(
      (t) =>
        t.location &&
        t.location.offset >= 0 &&
        t.location.offset + t.location.length <= original.length,
    )
    .map((t) => ({
      start: t.location!.offset,
      end: t.location!.offset + t.location!.length,
      severity: t.severity,
    }))
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const groups: Array<{ start: number; end: number; severity: Severity }> = [];
  for (const span of spans) {
    const last = groups[groups.length - 1];
    if (last && span.start <= last.end) {
      last.end = Math.max(last.end, span.end);
      if (RANK[span.severity] > RANK[last.severity]) last.severity = span.severity;
    } else {
      groups.push({ ...span });
    }
  }
  if (groups.length === 0) return null;

  const edits: TextEdit[] = [];
  const head = original.slice(0, groups[0].start);
  if (!sanitized.startsWith(head)) return null;
  let at = head.length;
  for (let k = 0; k < groups.length; k++) {
    const group = groups[k];
    const keep = original.slice(
      group.end,
      k + 1 < groups.length ? groups[k + 1].start : original.length,
    );
    let next: number;
    if (k + 1 < groups.length) {
      next = sanitized.indexOf(keep, at);
      if (next < 0) return null;
    } else {
      next = sanitized.length - keep.length;
      if (next < at || !sanitized.endsWith(keep)) return null;
    }
    edits.push({
      offset: group.start,
      length: group.end - group.start,
      replacement: sanitized.slice(at, next),
      severity: group.severity,
    });
    at = next + keep.length;
  }
  return edits;
}

/**
 * Replace each range of `content` in one pass, from the last offset to the first.
 *
 * This is what rebuilding the string once per edit gives, without the quadratic
 * cost (one slice of the whole text per finding, #160, #170). Each range's
 * offset is measured on the original text. `replacement` is the text for every
 * range, or a function of the original text a range covers. An empty
 * replacement removes the range.
 *
 * State: the result is `content.slice(0, boundary)` plus the chunks, which are
 * kept in reverse so the front is the last element. An edit that reaches past
 * `boundary` eats into the front of the chunks, as slicing the already-edited
 * string did. Output matches editing the string once per range whenever every
 * range fits the text and none overlap; an offset past the end now appends
 * instead of landing inside inserted text.
 */
export function replaceRanges(
  content: string,
  ranges: ReadonlyArray<{ offset: number; length: number }>,
  replacement: string | ((original: string) => string),
): string {
  const sorted = [...ranges].sort((a, b) => b.offset - a.offset);
  const chunks: string[] = [];
  let boundary = content.length;

  for (const { offset, length } of sorted) {
    const end = offset + length;

    if (end <= boundary) {
      if (end < boundary) chunks.push(content.slice(end, boundary));
    } else {
      let drop = end - boundary;
      while (drop > 0 && chunks.length > 0) {
        const front = chunks[chunks.length - 1];
        if (front.length <= drop) {
          drop -= front.length;
          chunks.pop();
        } else {
          chunks[chunks.length - 1] = front.slice(drop);
          drop = 0;
        }
      }
    }
    const text =
      typeof replacement === 'string' ? replacement : replacement(content.slice(offset, end));
    if (text) chunks.push(text);
    boundary = offset;
  }

  return content.slice(0, boundary) + chunks.reverse().join('');
}
