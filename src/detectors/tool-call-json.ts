/**
 * Finds the tool calls in a piece of text and the shell commands inside them.
 *
 * A router that rewrites a tool call keeps it valid JSON, so the structure is
 * the signal: an object with a tool name and an arguments value is a call, and
 * a `command` string inside the arguments is what runs. This reads JSON the way
 * a client would, in one pass over the text, without parsing the whole of it:
 *
 *  - keys and strings are decoded (`"command"` is `command`), so escaped
 *    keys and `|` do not hide anything;
 *  - a command key counts at any depth inside the arguments, after any other
 *    key or value, and every occurrence counts (a client keeps the last of a
 *    repeated key, so the first one is not the only one that runs);
 *  - arguments may be an object, or a string that holds a JSON object (the
 *    OpenAI shape), pretty-printed or not;
 *  - a command may be a string or an array of strings.
 *
 * Configuration files with a `command` key (hooks, MCP servers, plugin
 * manifests, build tools) have no tool name next to an arguments value, so they
 * are not calls.
 *
 * Every character is read once. A quote with no closing quote on its line is
 * skipped as a stray quote, along with the rest of the line.
 */

export interface Span {
  start: number;
  end: number;
}

/** The arguments of a tool call. `stringified` means `start..end` is the inside of a JSON string. */
export interface ArgumentSpan extends Span {
  stringified: boolean;
}

/** A shell command: the decoded text, and where it sits (inside its quotes) in the original. */
export interface CommandValue extends Span {
  text: string;
}

const NAME_KEYS = new Set(['name', 'tool', 'tool_name', 'toolname']);
/** Tool names look like identifiers; "Execute Command" and "install k3s" are labels. */
const TOOL_NAME = /^[A-Za-z_][\w.:-]{0,63}$/;
const CALL_TYPES =
  /^(?:local_shell_call|function_call|tool_use|tool_call|computer_call|custom_tool_call|mcp_call)$/i;
const ARG_KEYS = new Set(['input', 'arguments', 'args', 'tool_input', 'action']);
const COMMAND_KEYS = new Set([
  'command',
  'commands',
  'cmd',
  'command_line',
  'commandline',
  'script',
  'shell',
  'bash',
  'code',
]);

const isWhitespace = (c: number) => c === 32 || (c >= 9 && c <= 13);

/** The end of the line holding `from`: the next `\n` or `\r`, or the end of the text. */
function lineEnd(text: string, from: number): number {
  const n = text.length;
  for (let j = from; j < n; j++) {
    const c = text.charCodeAt(j);
    if (c === 10 || c === 13) return j;
  }
  return n;
}

/** Index of the quote that closes the string opened at `open`, or -1 at a line break or the end. */
function stringEnd(text: string, open: number): number {
  const n = text.length;
  for (let j = open + 1; j < n;) {
    const c = text.charCodeAt(j);
    if (c === 92) j += 2;
    else if (c === 34) return j;
    else if (c === 10 || c === 13) return -1;
    else j++;
  }
  return -1;
}

const SIMPLE_ESCAPES: Record<string, string> = {
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t',
};

/**
 * Decode the inside of a JSON string. `map[k]` is the index in `raw` where
 * decoded character `k` starts, and `map[text.length]` is `raw.length`. An
 * escape that is not valid JSON stays as written.
 */
export function decodeJsonString(raw: string): { text: string; map: Int32Array } {
  const n = raw.length;
  const map = new Int32Array(n + 1);
  let out = '';
  let i = 0;
  while (i < n) {
    const at = i;
    const c = raw[i];
    if (c !== '\\' || i + 1 >= n) {
      out += c;
      i++;
    } else {
      const e = raw[i + 1];
      if (e in SIMPLE_ESCAPES) {
        out += SIMPLE_ESCAPES[e];
        i += 2;
      } else if (e === 'u' && /^[0-9a-fA-F]{4}$/.test(raw.slice(i + 2, i + 6))) {
        out += String.fromCharCode(parseInt(raw.slice(i + 2, i + 6), 16));
        i += 6;
      } else {
        out += c;
        i++;
      }
    }
    // A code unit that came from one escape or one character starts at `at`.
    map[out.length - 1] = at;
  }
  map[out.length] = n;
  return { text: out, map: map.subarray(0, out.length + 1) };
}

/** The decoded key whose quotes are at `open` and `close`. */
function keyOf(text: string, open: number, close: number): string {
  const raw = text.slice(open + 1, close);
  return (raw.includes('\\') ? decodeJsonString(raw).text : raw).toLowerCase();
}

interface Frame {
  start: number;
  hasName: boolean;
  isArgs: boolean;
  args: ArgumentSpan[];
}

/**
 * The arguments of every tool call in `content`: the value of an arguments key
 * (`input`, `arguments`, `args`, `tool_input`, `action`) in an object that also
 * has a tool name (`name` or `tool` with an identifier as its value, or a
 * `type` such as `tool_use` or `local_shell_call`), in any key order and at any
 * depth.
 */
export function findToolCallArguments(content: string): ArgumentSpan[] {
  const found: ArgumentSpan[] = [];
  const stack: Frame[] = [];
  const n = content.length;
  let nextBraceIsArgs = false;

  const close = (end: number): void => {
    const frame = stack.pop();
    if (!frame) return;
    if (frame.isArgs && stack.length > 0) {
      stack[stack.length - 1].args.push({ start: frame.start, end, stringified: false });
    }
    if (frame.hasName) for (const span of frame.args) found.push(span);
  };

  let i = 0;
  while (i < n) {
    const c = content.charCodeAt(i);
    if (c === 34) {
      const end = stringEnd(content, i);
      if (end < 0) {
        // No closing quote on this line, so none of the later quotes on it has one either.
        i = lineEnd(content, i);
        continue;
      }
      let k = end + 1;
      while (k < n && isWhitespace(content.charCodeAt(k))) k++;
      if (content.charCodeAt(k) === 58 && stack.length > 0) {
        const top = stack[stack.length - 1];
        const key = keyOf(content, i, end);
        let v = k + 1;
        while (v < n && isWhitespace(content.charCodeAt(v))) v++;
        const first = content.charCodeAt(v);
        if (NAME_KEYS.has(key) || key === 'type') {
          if (first === 34) {
            const valueEnd = stringEnd(content, v);
            if (valueEnd > 0 && valueEnd - v <= 80) {
              const value = content.slice(v + 1, valueEnd);
              if (key === 'type' ? CALL_TYPES.test(value) : TOOL_NAME.test(value)) {
                top.hasName = true;
              }
            }
          }
        } else if (ARG_KEYS.has(key)) {
          if (first === 123) {
            nextBraceIsArgs = true;
          } else if (first === 34) {
            const valueEnd = stringEnd(content, v);
            if (valueEnd > 0) top.args.push({ start: v + 1, end: valueEnd, stringified: true });
          }
        }
        i = k + 1;
        continue;
      }
      i = end + 1;
      continue;
    }
    if (c === 123) {
      stack.push({ start: i, hasName: false, isArgs: nextBraceIsArgs, args: [] });
      nextBraceIsArgs = false;
    } else if (c === 125) {
      close(i + 1);
    }
    i++;
  }
  while (stack.length > 0) close(n);
  return found;
}

/**
 * The command strings in `text`, which is JSON: the string value of every
 * command key at any depth, and the strings of an array under one. `start` and
 * `end` are the inside of the quotes in `text`.
 */
function commandValuesIn(text: string): Array<Span & { value: string }> {
  const found: Array<Span & { value: string }> = [];
  const n = text.length;
  const take = (open: number): number => {
    const end = stringEnd(text, open);
    if (end < 0) return lineEnd(text, open);
    const raw = text.slice(open + 1, end);
    found.push({
      start: open + 1,
      end,
      value: raw.includes('\\') ? decodeJsonString(raw).text : raw,
    });
    return end + 1;
  };
  let i = 0;
  while (i < n) {
    if (text.charCodeAt(i) !== 34) {
      i++;
      continue;
    }
    const end = stringEnd(text, i);
    if (end < 0) {
      i = lineEnd(text, i);
      continue;
    }
    let k = end + 1;
    while (k < n && isWhitespace(text.charCodeAt(k))) k++;
    if (text.charCodeAt(k) !== 58) {
      i = end + 1;
      continue;
    }
    let v = k + 1;
    while (v < n && isWhitespace(text.charCodeAt(v))) v++;
    if (!COMMAND_KEYS.has(keyOf(text, i, end))) {
      i = k + 1;
      continue;
    }
    const first = text.charCodeAt(v);
    if (first === 34) {
      i = take(v);
    } else if (first === 91) {
      let depth = 1;
      let j = v + 1;
      while (j < n && depth > 0) {
        const c = text.charCodeAt(j);
        if (c === 34) j = take(j);
        else {
          if (c === 91) depth++;
          else if (c === 93) depth--;
          j++;
        }
      }
      i = j;
    } else {
      i = k + 1;
    }
  }
  return found;
}

/**
 * The shell commands of the tool calls in `content`, each with its decoded text
 * and its span in `content` (inside the quotes, so replacing it keeps the JSON
 * valid, escaped or not).
 */
export function findCommandValues(content: string): CommandValue[] {
  const seen = new Set<string>();
  const out: CommandValue[] = [];
  const add = (start: number, end: number, text: string) => {
    const key = `${start}:${end}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ start, end, text });
  };
  // An object inside another object is read with the outer one; reading it
  // again would make nested calls quadratic.
  const spans = findToolCallArguments(content).sort((a, b) => a.start - b.start || b.end - a.end);
  let outerEnd = -1;
  for (const args of spans) {
    if (!args.stringified) {
      if (args.end <= outerEnd) continue;
      outerEnd = args.end;
    }
    const raw = content.slice(args.start, args.end);
    if (!args.stringified) {
      for (const c of commandValuesIn(raw)) add(args.start + c.start, args.start + c.end, c.value);
    } else {
      const decoded = decodeJsonString(raw);
      // Arguments that are a bare string, not an object, are the command itself.
      if (!decoded.text.trimStart().startsWith('{')) add(args.start, args.end, decoded.text);
      for (const c of commandValuesIn(decoded.text)) {
        add(args.start + decoded.map[c.start], args.start + decoded.map[c.end], c.value);
      }
    }
  }
  return out;
}
