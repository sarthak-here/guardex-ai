# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Built-in topic scope provider using pluggable embedding encoders.

Delegates to TopicScopeEngine for actual ML work. This provider follows
the same pattern as GlinerPiiProvider and LlamaGuardClassifierProvider:
thin adapter over the ML engine, registered at startup.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from guardex._engine.ml.topic_scope_engine import TopicScopeEngine, ScopeProfile, TopicScopeResult

logger = logging.getLogger(__name__)


class SentenceTransformerScopeProvider:
    """Built-in topic scope provider using pluggable embedding encoders."""

    name: str = "guardex-scope-v2"

    def __init__(self, engine: TopicScopeEngine) -> None:
        self._engine = engine

    def build_scope(
        self,
        topics: list[str],
        utterances: dict[str, list[str]] | None = None,
        examples: list[str] | None = None,
        scope_width: str = "moderate",
        threshold: float | None = None,
    ) -> ScopeProfile:
        """Build a ScopeProfile from config.

        Delegates to TopicScopeEngine.build_scope() which computes
        embeddings for topics, utterances, and optional examples.
        ``threshold`` is stamped onto the returned profile so it travels
        with the profile to the matching call.
        """
        profile = self._engine.build_scope(
            topics, utterances=utterances, examples=examples, scope_width=scope_width,
        )
        if threshold is not None:
            profile.threshold = threshold
        return profile

    async def check_scope(
        self,
        text: str,
        scope_profile: ScopeProfile,
        threshold: float | None = None,
        alpha: float = 0.0,
    ) -> dict[str, Any]:
        """Check if text is within scope.

        Returns dict with keys:
            allowed: bool       -- True if text is on-topic
            distance: float     -- cosine distance to nearest topic
            matched_topic: str | None -- closest topic name
            confidence: float   -- confidence score (1.0 - distance)
            reason: str | None  -- human-readable rejection reason
        """
        # Sentence-transformer inference is CPU-bound; run off the event loop.
        result: TopicScopeResult = await asyncio.to_thread(
            self._engine.check,
            text, scope_profile, threshold=threshold, alpha=alpha,
        )
        return {
            "allowed": result.allowed,
            "distance": round(1.0 - result.similarity, 4),
            "matched_topic": result.matched_topic,
            "confidence": result.confidence,
            "reason": result.reason,
        }
