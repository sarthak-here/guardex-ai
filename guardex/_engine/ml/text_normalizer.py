# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Unicode / homoglyph / leet-speak normalization for classification.

Normalization is applied to the text sent for classification only - the
original user text is returned unchanged. Order matters:

1. Strip zero-width / invisible characters (break tokenization).
2. NFKC normalize (decompose confusable Unicode).
3. Strip inserted dots and spaces (``H.o.w`` → ``How``).
4. Expand leet speak (``h0w`` → ``how``).
5. Collapse excessive whitespace.
"""

from __future__ import annotations

import re
import unicodedata

# Used in adversarial attacks to break tokenizer boundaries (Unicode TR36 §4).
_INVISIBLE_CHARS = frozenset({
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u00ad",  # Soft Hyphen
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\u180e",  # Mongolian Vowel Separator
    "\ufff9",  # Interlinear Annotation Anchor
    "\ufffa",  # Interlinear Annotation Separator
    "\ufffb",  # Interlinear Annotation Terminator
})

# Compiled regex for invisible character removal
_INVISIBLE_RE = re.compile(
    "[" + "".join(re.escape(c) for c in _INVISIBLE_CHARS) + "]"
)

# Leet speak substitution map
# Source: Gröndahl et al. (2018) + Hosseini et al. (2017) adversarial examples.
# Only the most common substitutions - aggressive expansion risks false positives.
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
    "¥": "y",
    "€": "e",
    "£": "l",
}

_LEET_CHARS = frozenset(_LEET_MAP)

# Symbol-class leet chars that double as ordinary punctuation/currency.
# At token edges they are treated as punctuation, not substitutions, so
# "hello!" and "€50" survive while "k!ll" and "$ave" still expand.
_LEET_EDGE_PUNCT = "!@$+€£¥"

_TOKEN_RE = re.compile(r"\S+")

# Dot/space insertion pattern
# Catches: H.o.w, H-o-w, H o w (single char separated by delimiter)
# Won't match: U.S.A. (handled correctly because we require >=3 single chars)
_DOT_INSERT_RE = re.compile(
    r"(?<!\w)"                    # not preceded by word char
    r"([a-zA-Z])"                 # first letter
    r"(?:[.\-\s]([a-zA-Z])){2,}" # 2+ more letters separated by dot/dash/space
    r"(?!\w)"                     # not followed by word char
)


def _strip_invisible(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return _INVISIBLE_RE.sub("", text)


def _nfkc_normalize(text: str) -> str:
    """Apply NFKC normalization - decompose compatibility characters.

    NFKC maps confusable characters to their canonical forms:
    - Fullwidth: Ａ→A, ０→0
    - Ligatures: ﬁ→fi
    - Math symbols: ℌ→H
    - Circled: ①→1
    """
    return unicodedata.normalize("NFKC", text)


def _strip_dot_insertion(text: str) -> str:
    """Collapse deliberately separated letters: H.o.w → How, H o w → How."""
    def _collapse(m: re.Match) -> str:
        # Extract all single characters from the match
        return m.group(0).replace(".", "").replace("-", "").replace(" ", "")
    return _DOT_INSERT_RE.sub(_collapse, text)


def _expand_leet(text: str) -> str:
    """Expand leet speak inside word-like tokens only.

    A token is substituted when every character is either a letter or a
    leet character and it contains at least one of each ("k1ll", "h@te",
    "fr33dom"). Standalone numbers ("3 cats"), prices ("$500", "£50"),
    and tokens mixing non-leet digits ("route66") pass through unchanged -
    blanket substitution corrupted ordinary numeric text.
    """
    def _sub_token(m: re.Match) -> str:
        token = m.group(0)
        core = token.strip(_LEET_EDGE_PUNCT)
        if not core:
            return token
        prefix = token[: len(token) - len(token.lstrip(_LEET_EDGE_PUNCT))]
        suffix = token[len(prefix) + len(core):]
        has_letter = False
        has_leet = False
        for ch in core:
            if ch.isalpha():
                has_letter = True
            elif ch in _LEET_CHARS:
                has_leet = True
            else:
                return token
        if has_letter and has_leet:
            core = "".join(_LEET_MAP.get(c, c) for c in core)
        return prefix + core + suffix

    return _TOKEN_RE.sub(_sub_token, text)


def _collapse_whitespace(text: str) -> str:
    """Collapse multiple spaces/newlines to single space."""
    return re.sub(r"\s+", " ", text).strip()


def normalize_for_classification(text: str) -> str:
    """Normalize text for safety classification.

    Applies a pipeline of normalizations designed to defeat common
    adversarial evasion techniques while preserving semantic meaning.

    Parameters
    ----------
    text : str
        Raw user input.

    Returns
    -------
    str
        Normalized text suitable for classification.
        The original text should be preserved separately for the response.
    """
    result = text
    result = _strip_invisible(result)
    result = _nfkc_normalize(result)
    result = _strip_dot_insertion(result)
    result = _expand_leet(result)
    result = _collapse_whitespace(result)
    return result
