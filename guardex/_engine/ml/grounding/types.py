# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Result types for grounding checks."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SentenceGrounding:
    """Grounding result for a single sentence/claim."""

    sentence: str
    entailment: float       # hybrid-adjusted score (may be boosted by embedding similarity)
    contradiction: float
    neutral: float
    matched_chunk: str
    grounded: bool
    verdict: str  # "grounded" | "contradicted" | "ungrounded" | "uncertain"
    nli_entailment: float = 0.0  # raw NLI entailment before hybrid boost; used for chunk ranking


@dataclass(frozen=True, slots=True)
class GroundingResult:
    """Aggregate grounding result for a full response."""

    grounded: bool
    faithfulness_score: float
    has_contradiction: bool
    sentence_count: int
    grounded_count: int
    contradicted_count: int
    ungrounded_count: int
    uncertain_count: int
    details: list[SentenceGrounding] = field(default_factory=list)
    latency_ms: float = 0.0
    mode: str = ""
