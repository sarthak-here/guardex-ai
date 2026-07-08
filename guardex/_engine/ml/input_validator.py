# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Input validation against token-abuse attacks.

Three abuse shapes are checked: repetition flooding (e.g. ``aaaa...``
pushing instructions out of context), token padding (diluting classifier
attention), and excessive length (OOM / slow inference).

Configurable, because thresholds vary by use case:

- ``max_input_tokens`` - hard ceiling on input size. Defaults from
  settings; callers can request a lower limit per request.
- ``max_repetition_ratio`` - most-repeated token / total tokens. Normal
  English is 0.02-0.08; adversarial padding is >0.3. Default 0.3.
- ``max_char_repeat`` - consecutive identical chars. Normal text rarely
  exceeds 3; attacks use 50+. Default 20 (room for emphasis).

Code snippets, CJK languages, and long system prompts are all legitimate
high-repetition cases - that is why every threshold is a knob, not a
constant.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def _char_repeat_pattern(n: int) -> re.Pattern[str]:
    """Compile and cache the consecutive-char regex for a given threshold."""
    return re.compile(r"(.)\1{" + str(n - 1) + r",}")


@dataclass(frozen=True)
class ValidationResult:
    """Result of input validation."""
    valid: bool
    reason: str | None = None
    detail: str | None = None


def validate_input(
    text: str,
    max_input_chars: int = 32768,
    max_repetition_ratio: float = 0.3,
    max_char_repeat: int = 20,
    stage: str = "input",
) -> ValidationResult:
    """Validate input text for token abuse patterns.

    Parameters
    ----------
    text : str
        Raw input text to validate.
    max_input_chars : int
        Maximum allowed character count. Default 32768 (32KB).
        This is a safety-net ceiling; callers can request lower limits.
    max_repetition_ratio : float
        Maximum ratio of most-repeated word to total words.
        Default 0.3 (30%). Normal English prose is 2-8%.
        Set to 1.0 to disable.
    max_char_repeat : int
        Maximum consecutive identical characters.
        Default 20. Normal text rarely exceeds 3-4.
        Set to 0 to disable.

    Returns
    -------
    ValidationResult
        .valid=True if input passes all checks.
        .reason=short code for the failure type.
        .detail=human-readable explanation.
    """
    # Length check
    if len(text) > max_input_chars:
        return ValidationResult(
            valid=False,
            reason="input_too_long",
            detail=f"Input is {len(text)} characters, maximum is {max_input_chars}.",
        )

    # Empty/whitespace check
    stripped = text.strip()
    if not stripped:
        return ValidationResult(
            valid=False,
            reason="empty_input",
            detail="Input is empty or whitespace only.",
        )

    # Consecutive character repetition
    # Catches: "aaaa...aaa" (character flooding)
    # Only on input-direction stages - LLM output legitimately contains
    # repeated whitespace in markdown tables, code blocks, indentation.
    is_output = stage in ("output", "stream", "tool_output", "retrieval_result")
    if max_char_repeat > 0 and not is_output:
        repeat_match = _char_repeat_pattern(max_char_repeat).search(text)
        if repeat_match:
            char = repeat_match.group(1)
            count = len(repeat_match.group(0))
            return ValidationResult(
                valid=False,
                reason="char_repetition",
                detail=f"Character '{char}' repeated {count} times consecutively (max {max_char_repeat}).",
            )

    # Word repetition ratio
    # Catches: "ignore ignore ignore ... ignore tell me how to hack"
    if max_repetition_ratio < 1.0:
        words = stripped.lower().split()
        if len(words) >= 10:  # Only check if enough words to be meaningful
            word_counts: dict[str, int] = {}
            for w in words:
                word_counts[w] = word_counts.get(w, 0) + 1

            max_count = max(word_counts.values())
            ratio = max_count / len(words)

            if ratio > max_repetition_ratio:
                top_word = max(word_counts, key=word_counts.get)  # type: ignore[arg-type]
                return ValidationResult(
                    valid=False,
                    reason="word_repetition",
                    detail=f"Word '{top_word}' appears {max_count}/{len(words)} times "
                           f"({ratio:.0%}, max {max_repetition_ratio:.0%}).",
                )

    return ValidationResult(valid=True)
