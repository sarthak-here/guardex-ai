# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Grounding Engine - orchestrates speed and accuracy modes.

Models are injected via the constructor (see model_manager.py).
"""

from __future__ import annotations

import time
import logging

from .config import GroundingConfig, GroundingMode
from .claim_decomposer import decompose_claims
from .splitter import split_sentences
from .speed_checker import check_sentence_embedding, find_best_chunks
from .accuracy_checker import check_sentence_nli
from .types import GroundingResult, SentenceGrounding

logger = logging.getLogger(__name__)


class GroundingEngine:
    """Hybrid grounding engine with speed and accuracy modes.

    Speed mode:  embedding cosine similarity (~10ms)
    Accuracy mode: NLI cross-encoder + hybrid embedding fallback (~50-200ms)
    """

    def __init__(
        self,
        embedding_model,
        nli_model=None,
        config: GroundingConfig | None = None,
    ):
        self._embedding_model = embedding_model
        self._nli_model = nli_model
        self.config = config or GroundingConfig()

    @property
    def accuracy_available(self) -> bool:
        return self._nli_model is not None

    def check(
        self,
        response_text: str,
        sources: list[str],
        mode: GroundingMode | None = None,
        threshold: float | None = None,
    ) -> GroundingResult:
        """Check if a response is grounded in the source documents."""
        start = time.perf_counter()
        active_mode = mode or self.config.mode

        if active_mode == GroundingMode.ACCURACY and not self.accuracy_available:
            logger.warning("NLI model not loaded, falling back to speed mode")
            active_mode = GroundingMode.SPEED

        if not sources:
            # No sources to check against - caller asked us to verify against
            # nothing.  We cannot prove grounding, so return ungrounded.
            elapsed = (time.perf_counter() - start) * 1000
            return self._empty_result(active_mode, round(elapsed, 2), grounded=False)

        claims = decompose_claims(response_text, min_length=self.config.min_sentence_length)
        if not claims:
            claims = split_sentences(response_text, min_length=self.config.min_sentence_length)
        if not claims:
            # No verifiable claims in the response (e.g. empty string, pure
            # greeting, or only very short fragments below min_sentence_length).
            # With zero claims the "faithfulness" ratio is vacuously satisfied.
            elapsed = (time.perf_counter() - start) * 1000
            return self._empty_result(active_mode, round(elapsed, 2), grounded=True)

        effective_threshold = self.config.grounded_threshold if threshold is None else threshold

        if active_mode == GroundingMode.SPEED:
            details = self._check_speed(claims, sources, effective_threshold)
        else:
            details = self._check_accuracy(claims, sources, effective_threshold)

        grounded_count = sum(1 for d in details if d.verdict == "grounded")
        contradicted_count = sum(1 for d in details if d.verdict == "contradicted")
        ungrounded_count = sum(1 for d in details if d.verdict == "ungrounded")
        uncertain_count = sum(1 for d in details if d.verdict == "uncertain")

        sentence_count = len(details)
        faithfulness = grounded_count / sentence_count if sentence_count > 0 else 0.0
        has_contradiction = contradicted_count > 0

        overall_grounded = (
            faithfulness >= self.config.faithfulness_pass_threshold
            and not has_contradiction
        )

        elapsed = (time.perf_counter() - start) * 1000

        return GroundingResult(
            grounded=overall_grounded,
            faithfulness_score=round(faithfulness, 4),
            has_contradiction=has_contradiction,
            sentence_count=sentence_count,
            grounded_count=grounded_count,
            contradicted_count=contradicted_count,
            ungrounded_count=ungrounded_count,
            uncertain_count=uncertain_count,
            details=details,
            latency_ms=round(elapsed, 2),
            mode=active_mode.value,
        )

    def _empty_result(
        self,
        mode: GroundingMode,
        elapsed: float,
        grounded: bool = False,
    ) -> GroundingResult:
        """Result for the degenerate no-work cases.

        ``grounded`` should be True when there are no claims to verify
        (vacuously grounded) and False when there are no sources to verify
        against (cannot prove grounding).
        """
        return GroundingResult(
            grounded=grounded,
            faithfulness_score=1.0 if grounded else 0.0,
            has_contradiction=False,
            sentence_count=0,
            grounded_count=0,
            contradicted_count=0,
            ungrounded_count=0,
            uncertain_count=0,
            details=[],
            latency_ms=round(elapsed, 2),
            mode=mode.value,
        )

    def _check_speed(
        self, claims: list[str], sources: list[str], threshold: float
    ) -> list[SentenceGrounding]:
        results = []
        for claim in claims:
            result = check_sentence_embedding(
                sentence=claim,
                chunks=sources,
                model=self._embedding_model,
                threshold=threshold,
            )
            results.append(result)
        return results

    def _check_accuracy(
        self, claims: list[str], sources: list[str], threshold: float
    ) -> list[SentenceGrounding]:
        results = []
        for claim in claims:
            top_chunks = find_best_chunks(
                sentence=claim,
                chunks=sources,
                model=self._embedding_model,
                top_k=min(3, len(sources)),
            )

            best_result: SentenceGrounding | None = None
            for chunk_text, sim_score in top_chunks:
                result = check_sentence_nli(
                    sentence=claim,
                    chunk=chunk_text,
                    nli_model=self._nli_model,
                    threshold=threshold,
                    contradiction_threshold=self.config.contradiction_threshold,
                    embedding_similarity=sim_score,
                    hybrid_neutral_threshold=self.config.hybrid_neutral_threshold,
                )
                # Use raw NLI entailment for ranking to avoid biasing toward
                # hybrid-boosted results (where entailment may be inflated by embedding similarity)
                if best_result is None or result.nli_entailment > best_result.nli_entailment:
                    best_result = result

            if best_result is not None:
                results.append(best_result)
        return results
