# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Sentence splitting for grounding checks.

Splits LLM responses into atomic sentences for per-sentence NLI evaluation.
Handles common edge cases: abbreviations, decimals, bullet points, code blocks.
"""

from __future__ import annotations

import re

_ABBREV = re.compile(
    r"\b(?:Mr|Mrs|Ms|Dr|Prof|Sr|Jr|Inc|Ltd|Corp|vs|etc|approx|dept|est|govt|vol)\.",
    re.IGNORECASE,
)

_CODE_BLOCK = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_INLINE_CODE_LINE = re.compile(r"^`[^`]+`$")
_CODE_LINE = re.compile(
    r"^(?:"
    r"(?:import |from |def |class |if |for |while |return |print\()"
    r"|(?:pip install )"
    r"|(?:export )"
    r"|(?:guard\s*=|result\s*=|policy\s*=)"
    r"|(?:\w+\.\w+\()"
    r")"
)


def split_sentences(text: str, min_length: int = 10) -> list[str]:
    """Split text into sentences, filtering out code and tiny fragments."""
    if not text or not text.strip():
        return []

    cleaned = _CODE_BLOCK.sub("", text)
    protected = _ABBREV.sub(lambda m: m.group().replace(".", "<DOT>"), cleaned)
    protected = re.sub(r"(\d)\.([\d])", r"\1<DOT>\2", protected)

    parts = re.split(r"(?<=[.!?])\s+|\n+", protected)

    sentences = []
    for part in parts:
        restored = part.replace("<DOT>", ".").strip()
        restored = re.sub(r"^[\-\*•]\s+", "", restored)
        restored = re.sub(r"^\d+[.)]\s+", "", restored)

        if len(restored) < min_length:
            continue
        if _INLINE_CODE_LINE.match(restored):
            continue
        if _CODE_LINE.match(restored):
            continue

        alpha_ratio = sum(1 for c in restored if c.isalpha()) / max(len(restored), 1)
        if alpha_ratio < 0.4:
            continue

        sentences.append(restored)

    return sentences
