# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Keyword-based safety gate - first layer of the cascade.

Phrase-based, not single-word: single words like "kill" or "die" would
fire on "kill the process" or "die hard." Phrases require 2+ tokens and
express intent, not discussion.

The gate catches what both ONNX and LlamaGuard-1B miss: passive
ideation, indirect self-harm expression, polite planning language.
False positives are mitigated by requiring context words (first-person
pronouns, emotional qualifiers) and excluding academic/clinical patterns.

Primary category: S11 (suicide / self-harm). Secondary: S1 (specific
violent threat patterns).
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class KeywordMatch:
    """Result of a keyword gate check."""
    matched: bool
    pattern: str | None = None
    category: str = "S11"


# Passive suicidal ideation phrases
# Source: C-SSRS passive ideation items + Crisis Text Line analysis.
# Each pattern uses word boundaries (\b) to avoid partial matches.
# Patterns require first-person context to avoid matching educational content.

_SELF_HARM_PATTERNS: list[tuple[str, str]] = [
    # Passive ideation (C-SSRS Level 1)
    # "Wish to be dead" - most common passive ideation marker
    (r"\b(?:i|i\'m)\b.*\b(?:wish|want|hope)\b.*\b(?:dead|die|gone|disappear)\b", "S11"),
    (r"\b(?:wish|want|hope)\b.*\b(?:i was|i were|i\'m)\b.*\b(?:dead|gone|never born)\b", "S11"),

    # "Better off dead" - explicit passive ideation
    (r"\b(?:better off)\b.*\b(?:dead|without me|if i (?:was|were) gone)\b", "S11"),
    (r"\b(?:world|everyone|they)\b.*\b(?:better|happier)\b.*\b(?:without me|if i (?:was|were) gone)\b", "S11"),

    # "Nobody would care/notice" - hopelessness + self-erasure
    (r"\b(?:nobody|no one|noone)\b.*\b(?:care|notice|miss)\b.*\b(?:if i|if i\'m|when i)\b", "S11"),
    (r"\b(?:nobody|no one|noone)\b.*\b(?:would|will)\b.*\b(?:care|notice|miss me)\b", "S11"),

    # "Don't want to be alive/exist" - direct ideation
    (r"\b(?:don\'?t|do not)\b.*\b(?:want|deserve)\b.*\b(?:alive|live|exist|be here|wake up)\b", "S11"),

    # "Can't go on / can't take it anymore"
    (r"\b(?:i|i\'m)\b.*\b(?:can\'?t|cannot)\b.*\b(?:go on|take it|do this|keep going|keep living)\b", "S11"),

    # "Thinking about ending it" - active ideation language
    (r"\b(?:thinking|thought)\b.*\b(?:about|of)\b.*\b(?:ending it|killing myself|suicide|taking my life)\b", "S11"),
    (r"\b(?:end|ending)\b.*\b(?:my life|it all|everything)\b", "S11"),

    # "How to kill myself" - direct search for method
    (r"\b(?:how (?:to|do i|can i|should i))\b.*\b(?:kill myself|end my life|commit suicide)\b", "S11"),

    # Self-harm without suicidal intent
    (r"\b(?:i|i\'m)\b.*\b(?:cutting|burning|hurting)\b.*\b(?:myself|my (?:arm|wrist|leg|body))\b", "S11"),
    (r"\b(?:want|need|urge)\b.*\b(?:to (?:cut|burn|hurt|harm))\b.*\b(?:myself|me)\b", "S11"),

    # Specific threat patterns (S1 - violence)
    # These are calm, specific threats that ONNX misses (low toxicity score)
    (r"\b(?:i\'?m going to|i will|gonna)\b.*\b(?:shoot up|bomb|attack)\b.*\b(?:school|church|mosque|synagogue|temple|hospital|clinic|office|building|mall|store|concert|venue|theater|theatre|arena)\b", "S1"),
]

# Compile all patterns for performance (compiled once at import time)
_COMPILED_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE | re.DOTALL), category)
    for pattern, category in _SELF_HARM_PATTERNS
]

# Exclusion patterns
# Prevent false positives on clinical/educational/news content.
_EXCLUSION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(?:research|study|paper|article|report|statistics|data)\b.*\b(?:suicide|self.harm)\b", re.IGNORECASE),
    re.compile(r"\b(?:suicide|self.harm)\b.*\b(?:prevention|hotline|helpline|awareness|training|education)\b", re.IGNORECASE),
    re.compile(r"\b(?:signs|symptoms|risk factors|warning signs)\b.*\b(?:suicide|self.harm|depression)\b", re.IGNORECASE),
    re.compile(r"\b(?:how to help|supporting|counseling|therapy)\b.*\b(?:suicidal|depressed|self.harm)\b", re.IGNORECASE),
]


def check_keyword_gate(text: str) -> KeywordMatch:
    """Check text against the keyword safety gate.

    Returns a KeywordMatch indicating whether a dangerous pattern was found.
    This is the fastest gate in the cascade (~0ms) and catches passive
    ideation phrases that both ONNX and LlamaGuard-1B miss.

    Parameters
    ----------
    text : str
        Input text to check (should be already normalized if normalization is enabled).

    Returns
    -------
    KeywordMatch
        .matched=True if a dangerous pattern was found
        .pattern=the regex that matched (for audit logging)
        .category=the S-code category (S11 for self-harm, S1 for violence)
    """
    # Check patterns first - exclusions are only evaluated when a pattern fires
    matched: KeywordMatch | None = None
    for compiled, category in _COMPILED_PATTERNS:
        if compiled.search(text):
            matched = KeywordMatch(
                matched=True,
                pattern=compiled.pattern,
                category=category,
            )
            break

    if matched is None:
        return KeywordMatch(matched=False)

    # Pattern matched - check if this is legitimate educational/clinical content
    for exc_pattern in _EXCLUSION_PATTERNS:
        if exc_pattern.search(text):
            logger.debug(
                "GuardEx keyword gate: exclusion override applied (pattern=%s)",
                matched.pattern,
            )
            return KeywordMatch(matched=False)

    return matched
