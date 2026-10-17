/**
 * Regex sources for the tool-call-tampering patterns (#27).
 *
 * Two layers:
 *  - Bare shapes that no install guide writes (base64 piped into a shell,
 *    Python executing decoded text). They ship at `strict` only, because a
 *    security post can quote them.
 *  - Every shape inside the value of a command key of a tool call
 *    (`"command": "..."`): a download piped or chained into a shell, a shell
 *    run on a downloaded script, decoded text run by a shell or an
 *    interpreter, and PowerShell download-and-run. No install guide has that.
 *    These ship at `balanced`.
 *
 * A download piped into a shell as plain text is not flagged at all. An
 * install guide and an attack read the same there.
 */

/** A shell word. `ash`, `dash`, `ksh`, `csh`, `tcsh`, `zsh`, `bash`, `sh`, `fish`. */
const SHELL_NAME = String.raw`(?:(?:ba|z|da|k|c|tc|a)?sh|fish)`;
/** An optional path to the program, and an optional `env` in front of it. */
const ROOT = String.raw`(?:/(?:usr/)?(?:local/)?bin/)?(?:env\s+(?:-\S+\s+)*)?`;
const SUDO = String.raw`(?:sudo\s+(?:-\S+\s+)*)?`;
const IEX = String.raw`(?:iex|invoke-expression)\b`;
const INTERPRETER = String.raw`(?:python[23]?|node|perl|ruby)`;

/**
 * What a pipe may feed: a shell, `iex`, a bare interpreter (it reads the
 * script from stdin), or `python -`. `python -m json.tool` is not one.
 */
const PIPE_TARGET = String.raw`${SUDO}${ROOT}(?:${SHELL_NAME}\b|${IEX}|${INTERPRETER}(?=\s*(?:$|["'\\)|;&])|\s+-(?=[\s"'\\)|;&]|$)))`;

/**
 * What may follow `;` or `&&` after a download: make it executable, run a
 * shell, run a file in a temporary or relative path, source a file, or run a
 * script with an interpreter (`python -m` and `-c` are not scripts).
 */
export const CHAIN_TARGET = String.raw`(?:chmod\s+(?:\+x|[0-7]{3,4})\b|${SUDO}${ROOT}(?:${SHELL_NAME}\b|${IEX})|(?:\.{1,2}/|/(?:var/)?tmp/|/dev/shm/|~/)\S|(?:source|\.)\s+\S|${INTERPRETER}\s+(?!-[mce]\b)[./\w~-])`;

/** Whitespace, or a JSON escape for it (`\n`, or `\\n` inside a stringified value). */
const OPWS = String.raw`(?:\s|\\{1,2}[nrt])*`;
const PIPE_OP = String.raw`(?:\||\\u007[cC])`;

/** A word that fetches from the network. */
export const DOWNLOADER = String.raw`(?:\b(?:curl|wget|irm|iwr|invoke-webrequest|invoke-restmethod)\b|\\u0063url|\\u0077get)`;

/** The tail of a download that is run: a pipe into a target, or a chain into a target. */
export const RUN_AFTER_DOWNLOAD = String.raw`(?:${PIPE_OP}${OPWS}${PIPE_TARGET}|(?:;|&&)${OPWS}${CHAIN_TARGET})`;

const FETCH = String.raw`(?:curl|wget|irm|iwr)\b`;
const SHELL_OR_INTERPRETER = String.raw`(?<![\w.-])${ROOT}(?:${SHELL_NAME}|${INTERPRETER})`;

/**
 * A shell or interpreter run on a download: `bash -c "$(curl ...)"`,
 * `python3 -c "$(curl ...)"`, `sh <(curl ...)`, `bash < <(curl ...)`,
 * `source <(curl ...)`, `. <(curl ...)`, `eval "$(curl ...)"` and the same
 * with backticks.
 */
export const DOWNLOAD_SUBSHELL = String.raw`(?:${SHELL_OR_INTERPRETER}\s+(?:-\w+\s+)*-[ce]\s+(?:\\*["'])?(?:\$\(|\`)|(?:${SHELL_OR_INTERPRETER}|\bsource|(?<![\w.])\.)\s+(?:<\s*)?<\(|\b(?:eval|source)\s+(?:\\*["'])?(?:\$\(|\`)|(?<![\w.])\.\s+(?:\\*["'])?(?:\$\(|\`))\s*${FETCH}`;

const DECODER = String.raw`(?:base64\s+(?:-d|-D|-di|--decode)|xxd\s+-r(?:\s+-p)?|openssl\s+(?:enc\s+)?-?base64\s+-d)`;

/** `bash -c "$(echo B64 | base64 -d)"`: a shell run on decoded text. */
export const DECODE_SUBSHELL = String.raw`(?:${SHELL_OR_INTERPRETER}|\b(?:eval|source))\s+(?:-\w+\s+)*(?:\\*["'])?\$\(\s*(?:echo|printf)\s+(?:-\w+\s+)*(?:\\*["'])?[A-Za-z0-9+/=]{16,}(?:\\*["'])?\s*\|\s*${DECODER}\b`;

/** `... | base64 -d | sh`, `base64 -d <<< B64 | bash`, `xxd -r -p | sh`: decoded text run by a shell. */
export const BASE64_TO_SHELL = String.raw`\b${DECODER}\b(?:\s+-[\w=.-]+)*(?:\s*<<<\s*\S+)?\s*${PIPE_OP}${OPWS}${PIPE_TARGET}`;

/** `exec(base64.b64decode(...))`, `exec(zlib.decompress(base64.b64decode(...)))`, any module alias. */
export const PYTHON_B64_EXEC = String.raw`\b(?:exec|eval)\s*\(\s*(?:(?:\w+\.)?decompress\s*\(\s*)?(?:__import__\s*\(\s*\\*["'][\w.]+\\*["']\s*\)\s*\.|\w+\.)?(?:b64decode|a2b_base64)\s*\(`;

/** `iex (New-Object Net.WebClient).DownloadString(...)`, `iex (irm URL)` and `powershell -enc BASE64`. */
export const POWERSHELL_RUN = String.raw`(?:\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:new-object\s+(?:system\.)?net\.webclient|(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b)|\bpowershell(?:\.exe)?\s+(?:-\w+\s+)*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,})`;

const COMMAND_KEYS = String.raw`(?:command|commands|cmd|command_?line|script|shell|bash|code)`;
const ARGS_KEYS = String.raw`(?:tool_)?(?:input|arguments|args|parameters|params)`;
const NEST_KEYS = String.raw`(?:options|opts|config|params)`;

/**
 * A command key counts only as a tool call's argument: the first key of the
 * object under `input`, `arguments` and the like, or one that follows string
 * and number keys (and one level of `options`). Config files have `"command"`
 * keys too (hooks, MCP servers, plugin manifests), and one of them runs
 * `curl ... | sh` to install a tool. A leading key that holds some other
 * object or array ends the match; that ordering is not what a model writes
 * for a shell tool.
 *
 * Form 1 is plain JSON, or a Python dict's `'command': '...'`. Group 1 is the
 * quote of the command value. A character is anything but that quote; a
 * backslash takes the next character with it. The two alternatives start
 * differently, so a failed match never retries the same text another way.
 */
const PLAIN_STRING = String.raw`(?:"(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*')`;
const PLAIN_LEAD = String.raw`(?:\s*(?:"(?!${COMMAND_KEYS}")[^"\\\n]+"|'(?!${COMMAND_KEYS}')[^'\\\n]+')\s*:\s*(?:${PLAIN_STRING}|-?\w[\w.]*)\s*,)*`;
const PLAIN_NEST = String.raw`(?:\s*(?:"${NEST_KEYS}"|'${NEST_KEYS}')\s*:\s*\{${PLAIN_LEAD})?`;
const PLAIN_KEY = String.raw`(?:"${ARGS_KEYS}"|'${ARGS_KEYS}')\s*:\s*\{${PLAIN_LEAD}${PLAIN_NEST}\s*(?:"${COMMAND_KEYS}"|'${COMMAND_KEYS}')\s*:\s*`;
const PLAIN_SCALAR_OPEN = String.raw`${PLAIN_KEY}(["'])`;
const PLAIN_ARRAY_OPEN = String.raw`${PLAIN_KEY}\[\s*(?:${PLAIN_STRING}\s*,\s*)*(["'])`;
const PLAIN_CHAR = String.raw`(?:(?!\1)[^\\]|\\[\s\S])`;

/**
 * Form 2: arguments sent as a JSON string (the OpenAI shape), so every quote
 * inside shows up escaped: `"arguments": "{\"command\": \"...\"}"`. A
 * character is a plain character, a backslash with a plain character, or a
 * decoded backslash (`\\`) followed by a plain character, a quote (`\\\"`) or
 * another backslash (`\\\\`). Each token starts differently from the others,
 * and a bare `\"` matches none, so it ends the value.
 */
const ESCAPED_CHAR = String.raw`(?:[^\\"]|\\[^\\"]|\\\\[^\\"]|\\\\\\"|\\\\\\\\)`;
const ESCAPED_STRING = String.raw`\\"${ESCAPED_CHAR}*\\"`;
const ESCAPED_LEAD = String.raw`(?:\s*\\"(?!${COMMAND_KEYS}\\")(?:[^\\"]|\\[^"])+\\"\s*:\s*(?:${ESCAPED_STRING}|-?\w[\w.]*)\s*,)*`;
const ESCAPED_NEST = String.raw`(?:\s*\\"${NEST_KEYS}\\"\s*:\s*\{${ESCAPED_LEAD})?`;
const ESCAPED_KEY = String.raw`"${ARGS_KEYS}"\s*:\s*"\s*\{${ESCAPED_LEAD}${ESCAPED_NEST}\s*\\"${COMMAND_KEYS}\\"\s*:\s*`;
const ESCAPED_SCALAR_OPEN = String.raw`${ESCAPED_KEY}\\"`;
const ESCAPED_ARRAY_OPEN = String.raw`${ESCAPED_KEY}\[\s*(?:${ESCAPED_STRING}\s*,\s*)*\\"`;

/**
 * The four layouts of a command value: a string or an array of strings, in
 * plain JSON or in a stringified `arguments` value. `group` is the capture
 * group that holds the value's text: the pattern wraps it so a sanitized
 * result replaces the string value and nothing else, which keeps the JSON
 * valid.
 */
export const COMMAND_LAYOUTS = {
  plain: { open: PLAIN_SCALAR_OPEN, char: PLAIN_CHAR, group: 2 },
  'plain-array': { open: PLAIN_ARRAY_OPEN, char: PLAIN_CHAR, group: 2 },
  escaped: { open: ESCAPED_SCALAR_OPEN, char: ESCAPED_CHAR, group: 1 },
  'escaped-array': { open: ESCAPED_ARRAY_OPEN, char: ESCAPED_CHAR, group: 1 },
} as const;

export type CommandLayout = keyof typeof COMMAND_LAYOUTS;

/** `shape` somewhere inside the value of a command key. */
export function inCommand(layout: CommandLayout, shape: string): string {
  const { open, char } = COMMAND_LAYOUTS[layout];
  return String.raw`${open}(${char}*?${shape}${char}*)`;
}

/**
 * A download that is run, inside a command value. After the downloader word,
 * the filler may not contain another downloader word: the next one starts its
 * own attempt, so a run of them stays linear and still matches
 * (`curl -A curl https://x | sh` matches from the second word).
 */
export function downloadExecInCommand(layout: CommandLayout): string {
  const { open, char } = COMMAND_LAYOUTS[layout];
  return String.raw`${open}(${char}*?${DOWNLOADER}(?:(?!${DOWNLOADER})${char})*?${RUN_AFTER_DOWNLOAD}${char}*)`;
}
