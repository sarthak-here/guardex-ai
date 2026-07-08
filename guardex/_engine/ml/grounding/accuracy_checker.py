# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Accuracy mode: NLI cross-encoder grounding check with hybrid scoring.

Uses a pre-loaded DeBERTa cross-encoder (injected, not loaded here).
Hybrid scoring: when NLI returns "neutral", falls back to embedding similarity.
"""

from __future__ import annotations

import numpy as np

from .types import SentenceGrounding


def _softmax(logits: np.ndarray) -> np.ndarray:
    exp = np.exp(logits - np.max(logits))
    return exp / exp.sum()


def check_sentence_nli(
    sentence: str,
    chunk: str,
    nli_model,
    threshold: float = 0.55,
    contradiction_threshold: float = 0.7,
    embedding_similarity: float | None = None,
    hybrid_neutral_threshold: float = 0.65,
) -> SentenceGrounding:
    """Check if a sentence is grounded using NLI cross-encoder.

    Hybrid scoring: when NLI says "neutral" but embedding similarity is high,
    we treat the sentence as grounded.
    """
    logits = nli_model.predict([(chunk, sentence)])[0]
    probs = _softmax(np.array(logits, dtype=np.float64))

    # Resolve label indices dynamically so this works with any NLI cross-encoder,
    # not just cross-encoder/nli-deberta-v3-base (which uses [contradiction, entailment, neutral]).
    inner_model = getattr(nli_model, "model", None)
    config = getattr(inner_model, "config", None)
    id2label = getattr(config, "id2label", None) or {}
    label2idx = {str(v).lower(): k for k, v in id2label.items()} if id2label else {}
    contradiction_idx = label2idx.get("contradiction", 0)
    entailment_idx = label2idx.get("entailment", 1)
    neutral_idx = label2idx.get("neutral", 2)

    contradiction_score = float(probs[contradiction_idx])
    entailment_score = float(probs[entailment_idx])
    neutral_score = float(probs[neutral_idx])
    # Keep raw NLI score for chunk-ranking (not inflated by hybrid boost)
    raw_nli_entailment = entailment_score

    if entailment_score >= threshold:
        verdict = "grounded"
        grounded = True
    elif contradiction_score >= contradiction_threshold:
        verdict = "contradicted"
        grounded = False
    elif neutral_score > entailment_score and neutral_score > contradiction_score:
        if embedding_similarity is not None and embedding_similarity >= hybrid_neutral_threshold:
            verdict = "grounded"
            grounded = True
            entailment_score = max(entailment_score, embedding_similarity)
        elif embedding_similarity is not None and embedding_similarity >= 0.5:
            verdict = "uncertain"
            grounded = False
        else:
            verdict = "ungrounded"
            grounded = False
    elif entailment_score >= 0.3:
        verdict = "uncertain"
        grounded = False
    else:
        verdict = "ungrounded"
        grounded = False

    return SentenceGrounding(
        sentence=sentence,
        entailment=entailment_score,
        contradiction=contradiction_score,
        neutral=neutral_score,
        matched_chunk=chunk[:200],
        grounded=grounded,
        verdict=verdict,
        nli_entailment=raw_nli_entailment,
    )
