# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Claim decomposition: extract atomic factual claims from LLM responses.

Rule-based approach - no LLM needed.
"""

from __future__ import annotations

import re

_SKIP_PATTERNS = [
    re.compile(r"^(I |Let me |Here |Sure|Of course|Certainly)", re.IGNORECASE),
    re.compile(r"^(However|Additionally|Furthermore|Moreover|Also|Note that)", re.IGNORECASE),
    re.compile(r"^(If you |You can also |For more |Please |Feel free)", re.IGNORECASE),
    re.compile(r"^(The provided context does not|I don't have|I cannot)", re.IGNORECASE),
    re.compile(r"^(In summary|To summarize|Overall|In conclusion)", re.IGNORECASE),
]

_META_PATTERNS = [
    re.compile(r"not (?:detailed|mentioned|included|provided|specified|available|found|covered|stated|listed|described) in the (?:provided |given )?context", re.IGNORECASE),
    re.compile(r"(?:context|document|source) does not (?:contain|include|mention|provide|specify|cover|detail)", re.IGNORECASE),
    re.compile(r"(?:Use|Apply|Try|Ensure|Make sure|Remember to) .{0,30}(?:safely|carefully|properly|appropriately|accordingly|as needed)", re.IGNORECASE),
    re.compile(r"^(?:Use|Apply|Ensure|Remember|Make sure) (?:the |this |your )", re.IGNORECASE),
    re.compile(r"(?:refer to|consult|check|see) (?:the )?(?:official |full )?(?:documentation|docs|guide|manual)", re.IGNORECASE),
]

_FACTUAL_INDICATORS = [
    re.compile(r"\b(?:is|are|was|were|has|have|had|supports?|provides?|includes?|contains?|uses?|enables?|allows?)\b", re.IGNORECASE),
    re.compile(r"\b(?:checks?|detects?|validates?|returns?|sends?|receives?|processes?|creates?|generates?|runs?|stores?|handles?|performs?|implements?|requires?|accepts?|rejects?|blocks?|masks?|filters?|scans?|classif(?:y|ies)|identifies?)\b", re.IGNORECASE),
    re.compile(r"\b(?:can be|will be|should be|must be|designed to|built for|works by|known as|defined as|referred to)\b", re.IGNORECASE),
    re.compile(r"\b\d+\b"),
]

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


def decompose_claims(text: str, min_length: int = 25) -> list[str]:
    """Extract atomic factual claims from an LLM response."""
    if not text or not text.strip():
        return []

    cleaned = _CODE_BLOCK.sub("", text)
    parts = re.split(r"(?<=[.!?])\s+|\n+", cleaned)

    claims = []
    for part in parts:
        claim = part.strip()
        claim = re.sub(r"^[\-\*•]\s+", "", claim)
        claim = re.sub(r"^\d+[.)]\s+", "", claim)
        claim = re.sub(r"\*\*([^*]+)\*\*", r"\1", claim)
        claim = re.sub(r"__([^_]+)__", r"\1", claim)

        if len(claim) < min_length:
            continue
        if _INLINE_CODE_LINE.match(claim) or _CODE_LINE.match(claim):
            continue

        alpha_ratio = sum(1 for c in claim if c.isalpha()) / max(len(claim), 1)
        if alpha_ratio < 0.4:
            continue
        if any(p.match(claim) for p in _SKIP_PATTERNS):
            continue
        if any(p.search(claim) for p in _META_PATTERNS):
            continue

        is_factual = any(p.search(claim) for p in _FACTUAL_INDICATORS)
        if is_factual:
            claims.append(claim)

    if not claims:
        return _fallback_split(cleaned, min_length)

    return claims


def _fallback_split(text: str, min_length: int) -> list[str]:
    """Simple sentence split as fallback."""
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    sentences = []
    for part in parts:
        s = part.strip()
        s = re.sub(r"^[\-\*•]\s+", "", s)
        s = re.sub(r"^\d+[.)]\s+", "", s)
        if len(s) < min_length:
            continue
        alpha_ratio = sum(1 for c in s if c.isalpha()) / max(len(s), 1)
        if alpha_ratio < 0.4:
            continue
        if _CODE_LINE.match(s):
            continue
        sentences.append(s)
    return sentences
