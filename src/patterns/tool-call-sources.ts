/**
 * Regex sources for the tool-call-tampering patterns (#27).
 *
 * Two layers:
 *  - Bare shapes that no install guide writes (base64 piped into a shell,
 *    Python executing decoded text). They ship at `strict` only, because a
 *    security post can quote them.
 *  - Every shape inside the value of a command key of a tool call
 *    (`"command": "..."`): a download piped or chained into a shell, a shell
 *    run on a downloaded script, and the two above. No install guide has
 *    that. These ship at `balanced`.
 *
 * A download piped into a shell as plain text is not flagged at all. An
 * install guide and an attack read the same there.
 */

const SHELL_WORD = String.raw`(?:ba|z|da)?sh`;

/** What a pipe may feed: a shell, or `python -` (read the script from stdin). `python -m json.tool` is not one. */
const PIPE_TARGET = String.raw`(?:sudo\s+)?(?:${SHELL_WORD}\b|python[23]?\s+-(?=[\s"'\\)|;&]|$))`;

/** What may follow `;` or `&&` after a download: make it executable, or run a shell. */
const CHAIN_TARGET = String.raw`(?:chmod\s+(?:\+x|[0-7]{3,4})\b|(?:sudo\s+)?${SHELL_WORD}\b)`;

const DOWNLOADER = String.raw`\b(?:curl|wget)\b`;

/** `bash -c "$(curl ...)"`, `sh <(curl ...)`, `eval "$(curl ...)"`. */
export const DOWNLOAD_SUBSHELL = String.raw`\b(?:${SHELL_WORD}\s+(?:-\w+\s+)*-c\s+(?:\\*["'])?\$\(|${SHELL_WORD}\s+<\(|(?:eval|source)\s+(?:\\*["'])?\$\()\s*(?:curl|wget)\b`;

/** `... | base64 -d | sh`: decoded text run by a shell. */
export const BASE64_TO_SHELL = String.raw`\bbase64\s+(?:-d|-D|-di|--decode)\b(?:\s+-[\w=.-]+)*\s*\|\s*${PIPE_TARGET}`;

/** `exec(base64.b64decode(...))`: decoded text run by the interpreter. */
export const PYTHON_B64_EXEC = String.raw`\b(?:exec|eval)\s*\(\s*(?:__import__\s*\(\s*\\*["']base64\\*["']\s*\)\s*\.|base64\.)?b64decode\s*\(`;

const COMMAND_KEYS = String.raw`(?:command|cmd|script|shell|bash)`;
const ARGS_KEYS = String.raw`(?:tool_)?(?:input|arguments|args|parameters|params)`;

/**
 * A command key counts only as a tool call's argument: the first key of the
 * object under `input`, `arguments` and the like, or one that follows string
 * and number keys. Config files have `"command"` keys too (hooks, MCP servers,
 * plugin manifests), and one of them runs `curl ... | sh` to install a tool.
 * A leading key that holds an object or array ends the match; that ordering is
 * not what a model writes for a shell tool.
 *
 * Form 1 is plain JSON, or a Python dict's `'command': '...'`. Group 1 is the
 * quote of the command value. A character is anything but that quote; a
 * backslash takes the next character with it. The two alternatives start
 * differently, so a failed match never retries the same text another way.
 */
const PLAIN_STRING = String.raw`(?:"(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*')`;
const PLAIN_LEAD = String.raw`(?:\s*(?:"(?!${COMMAND_KEYS}")[^"\\\n]+"|'(?!${COMMAND_KEYS}')[^'\\\n]+')\s*:\s*(?:${PLAIN_STRING}|-?\w[\w.]*)\s*,)*`;
const PLAIN_OPEN = String.raw`(?:"${ARGS_KEYS}"|'${ARGS_KEYS}')\s*:\s*\{${PLAIN_LEAD}\s*(?:"${COMMAND_KEYS}"|'${COMMAND_KEYS}')\s*:\s*(["'])`;
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
const ESCAPED_LEAD = String.raw`(?:\s*\\"(?!${COMMAND_KEYS}\\")(?:[^\\"]|\\[^"])+\\"\s*:\s*(?:\\"${ESCAPED_CHAR}*\\"|-?\w[\w.]*)\s*,)*`;
const ESCAPED_OPEN = String.raw`"${ARGS_KEYS}"\s*:\s*"\s*\{${ESCAPED_LEAD}\s*\\"${COMMAND_KEYS}\\"\s*:\s*\\"`;

const FORMS = {
  plain: { open: PLAIN_OPEN, char: PLAIN_CHAR },
  escaped: { open: ESCAPED_OPEN, char: ESCAPED_CHAR },
} as const;

type CommandForm = keyof typeof FORMS;

/** `shape` somewhere inside the value of a command key. */
export function inCommand(form: CommandForm, shape: string): string {
  const { open, char } = FORMS[form];
  return String.raw`${open}${char}*?${shape}`;
}

/**
 * The download-and-run shape inside a command value. After the downloader
 * word, the filler may not contain another downloader word: the next one
 * starts its own attempt, so a run of them stays linear and still matches
 * (`curl -A curl https://x | sh` matches from the second word).
 */
export function downloadExecInCommand(form: CommandForm): string {
  const { open, char } = FORMS[form];
  return String.raw`${open}${char}*?${DOWNLOADER}(?:(?!${DOWNLOADER})${char})*?(?:\|\s*${PIPE_TARGET}|(?:;|&&)\s*${CHAIN_TARGET})`;
}
