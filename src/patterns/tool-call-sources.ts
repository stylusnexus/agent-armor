/**
 * Regex sources for the tool-call-tampering patterns (#27).
 *
 * Two layers:
 *  - Shapes that no install guide writes (base64 piped into a shell, Python
 *    executing decoded text), run on the whole text. They ship at `strict`
 *    only, because a security post can quote them.
 *  - Every shape, run only on the shell commands inside tool calls (scope
 *    `tool-call-command`): a download piped or chained into a shell, a shell
 *    run on a downloaded script, decoded text run by a shell or an
 *    interpreter, and PowerShell download-and-run. No install guide has that.
 *    These ship at `balanced`.
 *
 * A download piped into a shell as plain text is not flagged at all. An
 * install guide and an attack read the same there.
 *
 * The in-call regexes read decoded command text (escapes and unicode escapes
 * are already folded), so they match plain characters.
 */

/** A shell word. `ash`, `dash`, `ksh`, `csh`, `tcsh`, `zsh`, `bash`, `sh`, `fish`, quoted or as `$SHELL`. */
const SHELL_NAME = String.raw`(?:["'](?:(?:ba|z|da|k|c|tc|a)?sh|fish)(?=["'])|(?:(?:ba|z|da|k|c|tc|a)?sh|fish)(?![\w.-])|\$\{?SHELL\}?)`;
/** A wrapper that passes the program on: a path, `env`, `exec`, `command`, `busybox`, `nohup`. */
const ROOT = String.raw`(?:/(?:usr/)?(?:local/)?bin/)?(?:(?:env|exec|command|builtin|busybox|nohup|setsid|timeout|nice|ionice|stdbuf)[ \t]+(?:(?:-\S+|\d+|[A-Za-z_]\w*=\S*)[ \t]+)*)*`;
const SUDO = String.raw`(?:(?:sudo|doas)[ \t]+(?:-[uCgGhprRTt][ \t]+\S+[ \t]+|-\S+[ \t]+)*)?`;
const IEX = String.raw`(?:iex|invoke-expression)\b`;
const INTERPRETER = String.raw`(?:python[23]?|node|perl|ruby)`;

/**
 * What a pipe may feed: a shell, `iex`, a bare interpreter (it reads the
 * script from stdin), or `python -`. `python -m json.tool` is not one.
 */
export const PIPE_TARGET = String.raw`${SUDO}${ROOT}(?:${SHELL_NAME}|${IEX}|${INTERPRETER}(?=\s*(?:$|["'\\)|;&])|\s+-(?=[\s"'\\)|;&]|$)))`;

/**
 * What may follow `;`, `&&` or a line break after a download: make it
 * executable, run a shell, run a file in a temporary or relative path, source
 * a file, or run a script with an interpreter (`python -m` and `-c` are not
 * scripts).
 */
export const CHAIN_TARGET = String.raw`(?:chmod[ \t]+(?:[ugoa]*[+=][rwxst]*x|(?=[0-7]*[1357])[0-7]{3,4})\b|${SUDO}${ROOT}(?:${SHELL_NAME}|${IEX})|(?:\.{1,2}/|~/|\$\{?HOME\}?/|/(?:var/)?tmp/|/dev/shm/|/opt/|/usr/local/bin/|/home/|/root/)\S|(?:source|\.)[ \t]+\S|${INTERPRETER}[ \t]+(?!-[mce]\b)[./\w~-])`;

/** A word that fetches from the network. */
export const DOWNLOADER = String.raw`\b(?:curl|wget2?|irm|iwr|invoke-webrequest|invoke-restmethod)\b`;

/**
 * The tail of a download that is run: a pipe into a target, or a chain into a
 * target. A line break chains too, but is followed by spaces and tabs only, so
 * a run of line breaks is not rescanned from each one.
 */
export const RUN_AFTER_DOWNLOAD = String.raw`(?:\|&?\s*${PIPE_TARGET}|(?:;|&&)\s*${CHAIN_TARGET}|\n[ \t]*${CHAIN_TARGET})`;

/**
 * A download that is run. After the downloader word, the filler may not contain
 * another downloader word: the next one starts its own attempt, so a run of
 * them stays linear and still matches (`curl -A curl https://x | sh` matches
 * from the second word).
 */
export const DOWNLOAD_EXEC = String.raw`${DOWNLOADER}(?:(?!${DOWNLOADER})[\s\S])*?${RUN_AFTER_DOWNLOAD}`;

const FETCH = String.raw`(?:curl|wget2?|irm|iwr)\b`;
/**
 * A shell or interpreter word. Not preceded by the wrappers `ROOT` allows
 * after a pipe: starting at the word itself finds the same matches, and a
 * wrapper prefix tried at every position would rescan a run of `env env env`.
 */
const SHELL_OR_INTERPRETER = String.raw`(?<![\w.-])(?:${SHELL_NAME}|${INTERPRETER})`;

/**
 * A shell or interpreter run on a download: `bash -c "$(curl ...)"`,
 * `python3 -c "$(curl ...)"`, `sh <(curl ...)`, `bash < <(curl ...)`,
 * `bash <<< "$(curl ...)"`, `source <(curl ...)`, `. <(curl ...)`,
 * `eval "$(curl ...)"` and the same with backticks.
 */
export const DOWNLOAD_SUBSHELL = String.raw`(?:${SHELL_OR_INTERPRETER}[ \t]+(?:-\w+[ \t]+)*-\w*[ce][ \t]+["']?(?:\$\(|\`)|(?:${SHELL_OR_INTERPRETER}|\bsource|(?<![\w.])\.)[ \t]+(?:<\s*)?<\(|${SHELL_OR_INTERPRETER}[ \t]+<<<\s*["']?(?:\$\(|\`)|\b(?:eval|source)[ \t]+["']?(?:\$\(|\`)|(?<![\w.])\.[ \t]+["']?(?:\$\(|\`))\s*${FETCH}`;

const DECODER = String.raw`(?:base(?:64|32)[ \t]+(?:-d|-D|-di|--decode)|xxd[ \t]+-r(?:[ \t]+-p)?|openssl[ \t]+(?:enc[ \t]+)?-?base64[ \t]+-d)`;

const DECOMPRESSOR = String.raw`(?:gunzip|zcat|bzcat|xzcat|unxz|bunzip2|zstdcat|(?:gzip|bzip2|xz|zstd)[ \t]+-dc?)(?:[ \t]+-\S+)*`;

/** `bash -c "$(echo B64 | base64 -d)"`: a shell run on decoded text. */
export const DECODE_SUBSHELL = String.raw`(?:${SHELL_OR_INTERPRETER}|\b(?:eval|source))[ \t]+(?:-\w+[ \t]+)*["']?\$\(\s*(?:echo|printf)[ \t]+(?:-\w+[ \t]+)*["']?[A-Za-z0-9+/=]{16,}["']?\s*\|\s*${DECODER}\b`;

/** `... | base64 -d | sh`, `base64 -d <<< B64 | bash`, `xxd -r -p | sh`: decoded text run by a shell. */
export const BASE64_TO_SHELL = String.raw`\b${DECODER}\b(?:[ \t]+-[\w=.-]+)*(?:\s*<<<\s*\S+)?(?:\s*\|\s*${DECOMPRESSOR})*\s*\|&?\s*${PIPE_TARGET}`;

/**
 * Code run on decoded text: Python `exec(base64.b64decode(...))`,
 * `os.system(base64.b64decode(...))` and `exec(zlib.decompress(...))` (any
 * module alias), Node `eval(Buffer.from('...', 'base64'))` and `eval(atob(...))`,
 * Perl `eval decode_base64(...)`.
 */
export const DECODED_CODE_EXEC = String.raw`(?:\b(?:exec|eval|os\.system|os\.popen|subprocess\.\w+)\s*\(\s*(?:(?:\w+\.)?decompress\s*\(\s*)?(?:__import__\s*\(\s*["'][\w.]+["']\s*\)\s*\.|\w+\.)?(?:b64decode|a2b_base64)\s*\(|\b(?:eval|Function|exec|execSync|spawnSync|runInThisContext)\s*\(\s*(?:Buffer\.from|atob)\s*\(|\b(?:eval|system|exec)\s*\(?\s*(?:MIME::Base64::)?decode_base64\s*\()`;

/** A command that is only a substitution that runs a download: the element of `["bash", "-c", "$(curl ...)"]`. */
export const BARE_SUBSHELL = String.raw`^\s*["']?(?:\$\(|\`)\s*${FETCH}`;

/** `iex (New-Object Net.WebClient).DownloadString(...)`, `iex (irm URL)` and `powershell -enc BASE64`. */
export const POWERSHELL_RUN = String.raw`(?:\b(?:iex|invoke-expression)\s*\(?\s*\(?\s*(?:new-object[ \t]+(?:system\.)?net\.webclient|(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b)|\bpowershell(?:\.exe)?[ \t]+(?:-\w+[ \t]+(?:[A-Za-z]+[ \t]+)?)*-e(?:nc(?:odedcommand)?)?[ \t]+[A-Za-z0-9+/=]{20,})`;
