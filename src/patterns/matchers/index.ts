import type { PatternMatcher } from './types';
import { HIDDEN_HTML_MATCHERS } from './hidden-html';
import { AGENT_DIRECTED_COMMAND_MATCHERS } from './agent-directed-command';
import {
  BIDI_OVERRIDE_MATCHER,
  DAN_MATCHER,
  DATA_ATTR_MATCHER,
  HTML_COMMENT_MATCHER,
  LATEX_TINY_MATCHER,
  SYSTEM_PROMPT_MATCHER,
} from './spans';
import {
  ANTHROPIC_KEY_MATCHER,
  AWS_SECRET_MATCHER,
  JWT_MATCHER,
  META_TAG_MATCHER,
  OPENAI_KEY_MATCHER,
  SYSTEM_OVERRIDE_MATCHER,
} from './tokens';
import {
  BRACKET_COMMAND_MATCHER,
  CONDITIONAL_BOT_MATCHER,
  MARKDOWN_COMMENT_MATCHER,
  MARKDOWN_IMAGE_MATCHER,
} from './delimited';

export type { PatternMatcher, MatcherHit } from './types';

/** Every shipped matcher. Add new ones here. */
export const MATCHERS: PatternMatcher[] = [
  HTML_COMMENT_MATCHER,
  LATEX_TINY_MATCHER,
  DATA_ATTR_MATCHER,
  BIDI_OVERRIDE_MATCHER,
  SYSTEM_PROMPT_MATCHER,
  DAN_MATCHER,
  MARKDOWN_COMMENT_MATCHER,
  MARKDOWN_IMAGE_MATCHER,
  CONDITIONAL_BOT_MATCHER,
  BRACKET_COMMAND_MATCHER,
  META_TAG_MATCHER,
  SYSTEM_OVERRIDE_MATCHER,
  AWS_SECRET_MATCHER,
  OPENAI_KEY_MATCHER,
  ANTHROPIC_KEY_MATCHER,
  JWT_MATCHER,
  ...HIDDEN_HTML_MATCHERS,
  ...AGENT_DIRECTED_COMMAND_MATCHERS,
];

const BY_SOURCE = new Map<string, PatternMatcher>(
  MATCHERS.map((m) => [`${m.flags}\u0000${m.extractGroup}\u0000${m.regex}`, m]),
);

/** The matcher proven equivalent to exactly this regex source, flags and extract group, if any. */
export function findMatcher(regex: string, flags: string, extractGroup: number): PatternMatcher | undefined {
  return BY_SOURCE.get(`${flags}\u0000${extractGroup}\u0000${regex}`);
}
