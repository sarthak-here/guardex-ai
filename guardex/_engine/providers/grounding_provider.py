# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Grounding provider - async adapter over the synchronous GroundingEngine.

Wraps CPU-bound ML inference in asyncio.to_thread() to avoid blocking
the event loop, following the same pattern as TopicScopeProvider.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from guardex._engine.ml.grounding.engine import GroundingEngine
from guardex._engine.ml.grounding.config import GroundingMode

logger = logging.getLogger(__name__)


class GroundingProvider:
    """Provider adapter for the grounding engine."""

    name: str = "guardex-grounding-v1"

    def __init__(self, engine: GroundingEngine) -> None:
        self._engine = engine

    async def check_grounding(
        self,
        response_text: str,
        sources: list[str],
        mode: str | None = None,
        threshold: float | None = None,
    ) -> dict[str, Any]:
        """Run grounding check asynchronously."""
        grounding_mode = GroundingMode(mode) if mode else None

        result = await asyncio.to_thread(
            self._engine.check,
            response_text=response_text,
            sources=sources,
            mode=grounding_mode,
            threshold=threshold,
        )

        return {
            "grounded": result.grounded,
            "faithfulness_score": result.faithfulness_score,
            "has_contradiction": result.has_contradiction,
            "sentence_count": result.sentence_count,
            "grounded_count": result.grounded_count,
            "contradicted_count": result.contradicted_count,
            "ungrounded_count": result.ungrounded_count,
            "uncertain_count": result.uncertain_count,
            "details": [
                {
                    "sentence": s.sentence,
                    "entailment": round(s.entailment, 4),
                    "contradiction": round(s.contradiction, 4),
                    "neutral": round(s.neutral, 4),
                    "matched_chunk": s.matched_chunk,
                    "grounded": s.grounded,
                    "verdict": s.verdict,
                }
                for s in result.details
            ],
            "mode": result.mode,
            "latency_ms": result.latency_ms,
        }
