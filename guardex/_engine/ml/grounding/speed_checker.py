# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Speed mode: embedding similarity grounding check.

Uses a pre-loaded sentence-transformers bi-encoder (shared with TopicScope).
"""

from __future__ import annotations

import numpy as np

from .types import SentenceGrounding


def check_sentence_embedding(
    sentence: str,
    chunks: list[str],
    model,
    threshold: float = 0.55,
) -> SentenceGrounding:
    """Check if a sentence is grounded using embedding cosine similarity."""
    all_texts = [sentence] + chunks
    embeddings = model.encode(all_texts, normalize_embeddings=True)

    sentence_emb = embeddings[0]
    chunk_embs = embeddings[1:]

    similarities = chunk_embs @ sentence_emb
    best_idx = int(np.argmax(similarities))
    best_sim = float(similarities[best_idx])

    entailment = max(0.0, min(1.0, best_sim))
    neutral = max(0.0, 1.0 - entailment)
    contradiction = 0.0

    grounded = entailment >= threshold
    if grounded:
        verdict = "grounded"
    elif entailment >= 0.3:
        verdict = "uncertain"
    else:
        verdict = "ungrounded"

    return SentenceGrounding(
        sentence=sentence,
        entailment=entailment,
        contradiction=contradiction,
        neutral=neutral,
        matched_chunk=chunks[best_idx][:200],
        grounded=grounded,
        verdict=verdict,
    )


def find_best_chunks(
    sentence: str,
    chunks: list[str],
    model,
    top_k: int = 3,
) -> list[tuple[str, float]]:
    """Find the top-K best matching chunks for a sentence (NLI pre-filter)."""
    all_texts = [sentence] + chunks
    embeddings = model.encode(all_texts, normalize_embeddings=True)

    sentence_emb = embeddings[0]
    chunk_embs = embeddings[1:]

    similarities = chunk_embs @ sentence_emb
    k = min(top_k, len(chunks))
    top_indices = np.argsort(similarities)[-k:][::-1]
    return [(chunks[int(i)], float(similarities[i])) for i in top_indices]
