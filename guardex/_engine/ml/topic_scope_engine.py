# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Embedding-based topic scope engine.

Builds scope profiles from topic labels, optional examples, and optional
per-topic utterances using a pluggable ``EmbeddingProvider``. At query
time, embeds the query and ranks by cosine similarity against the stored
vectors. Optional BM25 sparse signal can be combined with the dense
score; ``fit()`` tunes thresholds from labeled data.

Usage::

    from guardex.encoders import SentenceTransformerEncoder, OpenAIEncoder
    from guardex._engine.ml.topic_scope_engine import TopicScopeEngine

    # Default encoder (backward compatible)
    engine = TopicScopeEngine()

    # Custom encoder
    engine = TopicScopeEngine(encoder=OpenAIEncoder(api_key="sk-..."))

    # Utterance-based scope (more precise than label-only)
    scope = engine.build_scope(
        topics=["banking", "insurance"],
        utterances={
            "banking": ["What's my balance?", "Transfer money", "Recent transactions"],
            "insurance": ["File a claim", "Policy coverage", "Premium payment"],
        },
        scope_width="moderate",
    )

    # Hybrid matching (dense + BM25 sparse)
    result = engine.check("What is my account balance?", scope, alpha=0.3)

    # Auto-tune thresholds from labeled data
    fitted_scope = engine.fit(
        scope, X=["balance?", "pizza"], y=["banking", None], n_iter=100
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# Module-level encoder cache - ensures only one SentenceTransformerEncoder
# is created per model name, regardless of how many TopicScopeEngine instances
# exist.  This replaces the old raw model singleton.
_encoder_cache: dict[str, Any] = {}
_encoder_cache_lock = threading.Lock()

# Short greeting-like inputs that should always be allowed through
_GREETING_PATTERNS = frozenset({
    "hi", "hello", "hey", "ok", "okay", "yes", "no", "thanks", "thank you",
    "bye", "goodbye", "sure", "please", "yo", "sup", "hola", "howdy",
    "good morning", "good evening", "good night", "good afternoon",
})

# Minimum query length (chars) below which we treat as greeting/pass-through
_MIN_QUERY_LENGTH = 3


# BM25 sparse scorer


class BM25Scorer:
    """Lightweight BM25 scorer for hybrid dense+sparse topic matching.

    Pre-built from a corpus of utterances at build_scope time.
    Scores a query against individual documents (utterances) at check time.
    """

    def __init__(
        self,
        documents: list[str],
        k1: float = 1.5,
        b: float = 0.75,
    ) -> None:
        self.k1 = k1
        self.b = b
        self.doc_count = len(documents)
        self.avg_dl = sum(len(d.split()) for d in documents) / max(len(documents), 1)
        self.doc_freqs: dict[str, int] = Counter()
        self.doc_terms: list[Counter] = []
        for doc in documents:
            terms = Counter(doc.lower().split())
            self.doc_terms.append(terms)
            for term in terms:
                self.doc_freqs[term] += 1

    def _score_terms(self, query_terms: list[str], doc_idx: int) -> float:
        """BM25 score of pre-tokenized query terms against document at doc_idx."""
        doc = self.doc_terms[doc_idx]
        dl = sum(doc.values())
        total = 0.0
        for term in query_terms:
            if term not in doc:
                continue
            tf = doc[term]
            df = self.doc_freqs.get(term, 0)
            idf = math.log((self.doc_count - df + 0.5) / (df + 0.5) + 1)
            total += idf * (tf * (self.k1 + 1)) / (
                tf + self.k1 * (1 - self.b + self.b * dl / self.avg_dl)
            )
        return total

    def score(self, query: str, doc_idx: int) -> float:
        """BM25 score of query against document at doc_idx."""
        return self._score_terms(query.lower().split(), doc_idx)

    def score_topics(self, query: str, utterance_labels: list[str]) -> dict[str, float]:
        """Score query against all documents, aggregate max score per topic."""
        query_terms = query.lower().split()
        topic_scores: dict[str, float] = {}
        for i, label in enumerate(utterance_labels):
            s = self._score_terms(query_terms, i)
            if label not in topic_scores or s > topic_scores[label]:
                topic_scores[label] = s
        return topic_scores


# Data classes


@dataclass(frozen=True)
class ScopeProfile:
    """Pre-computed scope representation.

    Attributes:
        centroid: Normalized centroid vector (average of all embeddings).
        topic_embeddings: Individual normalized topic centroid vectors.
        topic_labels: Original topic strings (parallel with topic_embeddings rows).
        scope_width: Preset name ("narrow"|"moderate"|"broad"|"fitted").
        threshold: Calibrated cosine similarity threshold.
        utterance_embeddings: Per-utterance vectors for fine-grained matching.
        utterance_labels: Topic label for each utterance (parallel with utterance_embeddings).
        bm25_scorer: Pre-built BM25 scorer for hybrid matching. None if no utterances.
        config_hash: Deterministic hash of the config used to build this profile.
    """

    centroid: np.ndarray
    topic_embeddings: np.ndarray
    topic_labels: list[str]
    scope_width: str
    threshold: float
    # New fields for utterance-based + hybrid matching
    utterance_embeddings: np.ndarray | None = None
    utterance_labels: list[str] = field(default_factory=list)
    bm25_scorer: BM25Scorer | None = field(default=None, repr=False, hash=False, compare=False)
    config_hash: str = ""
    # Pre-computed lookup for check() hot path (avoids rebuild per query)
    _utt_topic_indices: np.ndarray | None = field(default=None, repr=False, hash=False, compare=False)


@dataclass(frozen=True)
class TopicScopeResult:
    """Result of a single topic scope check.

    Attributes:
        allowed: True if the query is considered in-scope.
        similarity: Cosine similarity to closest match (0-1).
        matched_topic: Label of the closest individual topic, or None.
        confidence: How confident we are the query is in-scope (0.0-1.0).
        reason: Human-readable explanation of the decision.
    """

    allowed: bool
    similarity: float
    matched_topic: str | None
    confidence: float
    reason: str | None = None


# Threshold presets

_SCOPE_WIDTH_THRESHOLDS: dict[str, float] = {
    "narrow": 0.40,    # Strict - only clearly on-topic passes
    "moderate": 0.30,  # Balanced - allows related queries (calibrated on all-MiniLM-L6-v2)
    "broad": 0.20,     # Permissive - only clearly off-topic blocked
    "fitted": 0.30,    # Placeholder - overridden by fit()
}

_DEFAULT_SCOPE_WIDTH = "moderate"


# Engine


class TopicScopeEngine:
    """Embedding-based topic scope checker with pluggable encoders.

    Computes scope profiles from topic descriptions, optional examples, and
    optional per-topic utterances. Supports hybrid dense+sparse matching,
    per-category threshold optimization, and disk-based embedding persistence.
    """

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        encoder: Any | None = None,
        cache_dir: str | Path | None = None,
    ) -> None:
        """Initialize the engine.

        Args:
            model_name: Sentence-transformer model name (used if encoder is None).
            encoder: An EmbeddingProvider instance (from guardex.encoders).
                     If provided, model_name is ignored.
            cache_dir: Directory for embedding persistence cache.
                       Default: ~/.cache/guardex/scope
                       Set to None to disable caching.
        """
        if encoder is not None:
            self._encoder = encoder
        else:
            # Backward compat: delegate to SentenceTransformerEncoder
            # with module-level caching so only one instance per model name.
            self._encoder = self._get_or_create_encoder(model_name)

        self._cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".cache" / "guardex" / "scope"

    # Encoder caching

    @staticmethod
    def _get_or_create_encoder(model_name: str) -> Any:
        """Return a cached SentenceTransformerEncoder for the given model name."""
        cached = _encoder_cache.get(model_name)
        if cached is not None:
            return cached

        with _encoder_cache_lock:
            cached = _encoder_cache.get(model_name)
            if cached is not None:
                return cached

            from guardex.encoders import SentenceTransformerEncoder
            encoder = SentenceTransformerEncoder(model_name=model_name)
            _encoder_cache[model_name] = encoder
            return encoder

    # Embedding helpers

    def _embed(self, texts: list[str]) -> np.ndarray:
        """Embed a list of texts, returning normalized vectors."""
        return self._encoder.encode(texts, normalize=True).astype(np.float32)

    def _embed_single(self, text: str) -> np.ndarray:
        """Embed a single text string, returning a 1-D normalized vector."""
        return self._embed([text])[0]

    def _get_dimensions(self) -> int:
        """Get the embedding dimensionality."""
        return self._encoder.dimensions

    # Cache helpers

    @staticmethod
    def _compute_config_hash(
        topics: list[str],
        utterances: dict[str, list[str]] | None,
        examples: list[str] | None,
        scope_width: str,
        encoder_name: str,
    ) -> str:
        """Deterministic hash of a scope configuration."""
        payload = json.dumps(
            {
                "t": sorted(topics),
                "u": {k: sorted(v) for k, v in sorted(utterances.items())} if utterances else None,
                "e": sorted(examples) if examples else None,
                "w": scope_width,
                "e_name": encoder_name,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _cache_path(self, config_hash: str) -> Path:
        """Path to the cached .npz file for a config hash."""
        return self._cache_dir / f"{config_hash}.npz"

    def _load_cached(self, config_hash: str) -> ScopeProfile | None:
        """Load a ScopeProfile from cache if it exists."""
        path = self._cache_path(config_hash)
        if not path.exists():
            return None
        try:
            data = np.load(path, allow_pickle=False)
            utt_emb = data["utterance_embeddings"] if "utterance_embeddings" in data else None
            utt_labels = list(data["utterance_labels"]) if "utterance_labels" in data else []

            bm25 = None
            if utt_labels:
                utt_texts_raw = data["utterance_texts"] if "utterance_texts" in data else None
                if utt_texts_raw is not None:
                    utt_texts = list(utt_texts_raw)
                    bm25 = BM25Scorer(utt_texts)

            return ScopeProfile(
                centroid=data["centroid"],
                topic_embeddings=data["topic_embeddings"],
                topic_labels=list(data["topic_labels"]),
                scope_width=str(data["scope_width"]),
                threshold=float(data["threshold"]),
                utterance_embeddings=utt_emb,
                utterance_labels=utt_labels,
                bm25_scorer=bm25,
                config_hash=config_hash,
            )
        except (OSError, ValueError, KeyError, EOFError) as exc:
            logger.warning("Failed to load cached scope profile %s, rebuilding: %s", path, exc)
            return None

    def _save_cache(
        self,
        profile: ScopeProfile,
        utterance_texts: list[str] | None = None,
    ) -> None:
        """Persist a ScopeProfile to disk."""
        if not profile.config_hash:
            return
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            save_dict: dict[str, Any] = {
                "centroid": profile.centroid,
                "topic_embeddings": profile.topic_embeddings,
                "topic_labels": np.array(profile.topic_labels),
                "scope_width": profile.scope_width,
                "threshold": profile.threshold,
                "utterance_labels": np.array(profile.utterance_labels) if profile.utterance_labels else np.array([]),
            }
            if profile.utterance_embeddings is not None:
                save_dict["utterance_embeddings"] = profile.utterance_embeddings
            if utterance_texts:
                save_dict["utterance_texts"] = np.array(utterance_texts)
            target = self._cache_path(profile.config_hash)
            tmp = target.with_suffix(".tmp.npz")
            np.savez(tmp, **save_dict)
            tmp.replace(target)
            logger.debug("Scope profile cached: %s", profile.config_hash)
        except OSError as exc:
            logger.warning("Failed to cache scope profile: %s", exc)

    # Scope construction

    def build_scope(
        self,
        topics: list[str],
        utterances: dict[str, list[str]] | None = None,
        examples: list[str] | None = None,
        scope_width: str = _DEFAULT_SCOPE_WIDTH,
        use_cache: bool = True,
    ) -> ScopeProfile:
        """Pre-compute scope profile from topics, utterances, and examples.

        Args:
            topics: List of topic label strings (e.g. ["banking", "insurance"]).
            utterances: Optional dict mapping topic → list of example phrases.
                        When provided, topic centroids are computed from utterances
                        instead of from the topic label alone. Much more precise.
            examples: Optional list of general example queries (mixed into centroid).
            scope_width: "narrow", "moderate", "broad", or "fitted".
            use_cache: If True, check disk cache before re-computing.

        Returns:
            A ``ScopeProfile`` with cached vectors and threshold.
        """
        if scope_width not in _SCOPE_WIDTH_THRESHOLDS:
            raise ValueError(
                f"Unknown scope_width '{scope_width}'. "
                f"Choose from: {list(_SCOPE_WIDTH_THRESHOLDS.keys())}"
            )

        threshold = _SCOPE_WIDTH_THRESHOLDS[scope_width]

        # Handle empty topics
        if not topics:
            logger.warning("build_scope called with empty topics list. Scope will allow everything.")
            dim = self._get_dimensions()
            return ScopeProfile(
                centroid=np.zeros(dim, dtype=np.float32),
                topic_embeddings=np.empty((0, dim), dtype=np.float32),
                topic_labels=[],
                scope_width=scope_width,
                threshold=threshold,
            )

        # Deduplicate topics (duplicate names corrupt centroid computation)
        seen_topics: set[str] = set()
        deduped: list[str] = []
        for t in topics:
            if t in seen_topics:
                logger.warning("Duplicate topic '%s' in build_scope - ignoring duplicate.", t)
            else:
                seen_topics.add(t)
                deduped.append(t)
        topics = deduped

        encoder_name = self._encoder.name
        config_hash = self._compute_config_hash(topics, utterances, examples, scope_width, encoder_name)

        # Check cache
        if use_cache:
            cached = self._load_cached(config_hash)
            if cached is not None:
                logger.info("Loaded scope profile from cache: %s", config_hash)
                return cached

        t0 = time.perf_counter()

        all_utterance_texts: list[str] = []
        all_utterance_labels: list[str] = []
        utterance_embeddings: np.ndarray | None = None
        bm25: BM25Scorer | None = None

        if utterances:
            # Warn about orphaned utterance keys (likely typos)
            orphaned = set(utterances.keys()) - set(topics)
            if orphaned:
                logger.warning(
                    "build_scope: utterance keys not in topics list (ignored): %s",
                    orphaned,
                )
            # Utterance-based: embed all utterances, compute per-topic centroids
            for topic in topics:
                phrases = utterances.get(topic, [])
                all_utterance_texts.extend(phrases)
                all_utterance_labels.extend([topic] * len(phrases))

            if all_utterance_texts:
                utterance_embeddings = self._embed(all_utterance_texts)

                # Per-topic centroid = mean of that topic's utterance vectors
                topic_centroids = []
                for topic in topics:
                    mask = np.array([l == topic for l in all_utterance_labels])
                    if mask.any():
                        centroid_vec = utterance_embeddings[mask].mean(axis=0)
                        norm = np.linalg.norm(centroid_vec)
                        if norm > 0:
                            centroid_vec = centroid_vec / norm
                        topic_centroids.append(centroid_vec)
                    else:
                        # Fallback: embed the topic label itself
                        topic_centroids.append(self._embed_single(topic))
                topic_embeddings = np.array(topic_centroids, dtype=np.float32)

                # BM25 scorer from utterance texts
                bm25 = BM25Scorer(all_utterance_texts)
            else:
                # No actual utterances provided despite dict - fall back to labels
                topic_embeddings = self._embed(topics)
        else:
            # Label-only mode (original behavior)
            topic_embeddings = self._embed(topics)

        # Compute overall centroid from all available embeddings
        centroid_sources = [topic_embeddings]
        if examples:
            example_embeddings = self._embed(examples)
            centroid_sources.append(example_embeddings)
        if utterance_embeddings is not None:
            centroid_sources.append(utterance_embeddings)

        all_vecs = np.vstack(centroid_sources)
        centroid = all_vecs.mean(axis=0)
        centroid_norm = np.linalg.norm(centroid)
        if centroid_norm > 0:
            centroid = centroid / centroid_norm

        elapsed = (time.perf_counter() - t0) * 1000
        logger.info(
            "Scope built: %d topics, %d utterances, %d examples, width=%s, "
            "threshold=%.2f (%.1f ms)",
            len(topics),
            len(all_utterance_texts),
            len(examples) if examples else 0,
            scope_width,
            threshold,
            elapsed,
        )

        # Pre-compute utterance→topic index mapping for check() hot path
        utt_topic_indices = None
        if all_utterance_labels:
            label_to_idx = {lbl: i for i, lbl in enumerate(topics)}
            utt_topic_indices = np.array(
                [label_to_idx.get(lbl, -1) for lbl in all_utterance_labels]
            )

        profile = ScopeProfile(
            centroid=centroid.astype(np.float32),
            topic_embeddings=topic_embeddings.astype(np.float32),
            topic_labels=list(topics),
            scope_width=scope_width,
            threshold=threshold,
            utterance_embeddings=utterance_embeddings,
            utterance_labels=all_utterance_labels,
            bm25_scorer=bm25,
            config_hash=config_hash,
            _utt_topic_indices=utt_topic_indices,
        )

        # Make arrays read-only to prevent accidental mutation of shared state
        profile.centroid.flags.writeable = False
        profile.topic_embeddings.flags.writeable = False
        if profile.utterance_embeddings is not None:
            profile.utterance_embeddings.flags.writeable = False
        if profile._utt_topic_indices is not None:
            profile._utt_topic_indices.flags.writeable = False

        # Persist to cache
        if use_cache:
            self._save_cache(profile, all_utterance_texts or None)

        return profile

    # Query checking

    def check(
        self,
        query: str,
        scope: ScopeProfile,
        threshold: float | None = None,
        alpha: float = 0.0,
    ) -> TopicScopeResult:
        """Check if a query is within the defined scope.

        Args:
            query: The user's input text.
            scope: Pre-computed ``ScopeProfile`` from ``build_scope()``.
            threshold: Override the scope's calibrated threshold (optional).
            alpha: Hybrid matching weight (0.0 = dense only, 1.0 = sparse only).
                   Recommended: 0.3 for hybrid. Only used when scope has BM25.

        Returns:
            ``TopicScopeResult`` with allowed, similarity, matched_topic, confidence.
        """
        if not (0.0 <= alpha <= 1.0):
            raise ValueError(f"alpha must be in [0.0, 1.0], got {alpha}")
        if alpha > 0.7:
            logger.warning(
                "alpha=%.2f is very high - semantic matching contributes <30%%. "
                "Consider alpha <= 0.5 for meaningful embedding-based filtering.",
                alpha,
            )

        # Empty scope = allow everything
        if len(scope.topic_labels) == 0:
            return TopicScopeResult(
                allowed=True,
                similarity=1.0,
                matched_topic=None,
                confidence=1.0,
                reason="No scope restriction configured.",
            )

        # Greeting / very short query pass-through
        query_stripped = query.strip().lower()
        if len(query_stripped) < _MIN_QUERY_LENGTH or query_stripped in _GREETING_PATTERNS:
            return TopicScopeResult(
                allowed=True,
                similarity=1.0,
                matched_topic=None,
                confidence=1.0,
                reason="Greeting or short query - allowed by default.",
            )

        effective_threshold = threshold if threshold is not None else scope.threshold

        # Embed query
        query_vec = self._embed_single(query)

        # Cosine similarity to centroid
        centroid_similarity = float(np.dot(query_vec, scope.centroid))

        # Dense similarity per topic centroid
        topic_similarities = scope.topic_embeddings @ query_vec  # (N,)

        # If utterance-level embeddings exist, also check fine-grained matches
        if scope.utterance_embeddings is not None and len(scope.utterance_labels) > 0:
            utt_sims = scope.utterance_embeddings @ query_vec
            # Use pre-computed indices if available, else compute on the fly
            if scope._utt_topic_indices is not None:
                utt_topic_indices = scope._utt_topic_indices
            else:
                label_to_idx = {lbl: i for i, lbl in enumerate(scope.topic_labels)}
                utt_topic_indices = np.array(
                    [label_to_idx.get(lbl, -1) for lbl in scope.utterance_labels]
                )
            valid = utt_topic_indices >= 0
            if valid.any():
                utt_max_per_topic = np.full(len(scope.topic_labels), -np.inf)
                np.maximum.at(utt_max_per_topic, utt_topic_indices[valid], utt_sims[valid])
                has_utterance = utt_max_per_topic > -np.inf
                topic_similarities[has_utterance] = np.maximum(
                    topic_similarities[has_utterance], utt_max_per_topic[has_utterance]
                )

        # Hybrid: blend with BM25 sparse scores
        if alpha > 0.0 and scope.bm25_scorer is not None:
            sparse_scores = scope.bm25_scorer.score_topics(query, scope.utterance_labels)
            # Normalize sparse scores to [0, 1]
            max_sparse = max(sparse_scores.values()) if sparse_scores else 0.0
            for i, label in enumerate(scope.topic_labels):
                sparse_norm = (
                    sparse_scores.get(label, 0.0) / max_sparse if max_sparse > 0 else 0.0
                )
                # Clamp dense to [0, 1] before blending to match sparse range
                dense_clamped = max(0.0, float(topic_similarities[i]))
                topic_similarities[i] = (1 - alpha) * dense_clamped + alpha * sparse_norm

        best_topic_idx = int(np.argmax(topic_similarities))
        best_topic_similarity = float(topic_similarities[best_topic_idx])
        matched_topic = scope.topic_labels[best_topic_idx]

        # Decision: use the MAX of centroid and best-topic similarity
        max_similarity = max(centroid_similarity, best_topic_similarity)

        allowed = max_similarity >= effective_threshold
        confidence = min(1.0, max(0.0, max_similarity))

        # Build explanation
        if allowed:
            reason = (
                f"Query matches topic '{matched_topic}' "
                f"(similarity={best_topic_similarity:.3f}, threshold={effective_threshold:.2f})."
            )
        else:
            reason = (
                f"Query is off-topic. Closest topic '{matched_topic}' "
                f"(similarity={best_topic_similarity:.3f}) below threshold ({effective_threshold:.2f})."
            )

        return TopicScopeResult(
            allowed=allowed,
            similarity=max_similarity,
            matched_topic=matched_topic if best_topic_similarity > 0.1 else None,
            confidence=confidence,
            reason=reason,
        )

    # Threshold optimization

    def fit(
        self,
        scope: ScopeProfile,
        X: list[str],
        y: list[str | None],
        n_iter: int = 100,
        alpha: float = 0.0,
        seed: int | None = None,
    ) -> ScopeProfile:
        """Optimize the similarity threshold from labeled data.

        Uses random search over threshold space, maximizing F-beta score
        with beta=2 (recall-weighted - for safety-critical systems, false
        negatives are worse than false positives).

        Args:
            scope: Existing ScopeProfile to optimize.
            X: List of example query strings.
            y: List of labels - topic name (str) if in-scope, None if off-topic.
            n_iter: Number of random threshold candidates to try.
            alpha: Hybrid matching alpha (passed to internal scoring).
            seed: Random seed for reproducibility. None = non-deterministic.

        Returns:
            New ScopeProfile with optimized threshold and scope_width="fitted".
        """
        if len(X) != len(y):
            raise ValueError(f"X and y must have same length, got {len(X)} and {len(y)}")
        if not X:
            raise ValueError("Need at least one example to fit")

        # Embed all queries and pre-compute similarities once
        embeddings = self._embed(X)
        # (N_queries, N_topics) - avoids recomputing per iteration
        all_max_sims = np.max(embeddings @ scope.topic_embeddings.T, axis=1)
        actual_in_scope = np.array([label is not None for label in y])

        rng = np.random.default_rng(seed)

        best_threshold = scope.threshold
        best_f_beta = 0.0

        for _ in range(n_iter):
            candidate = float(rng.uniform(0.05, 0.85))

            predicted = all_max_sims >= candidate
            tp = int(np.sum(predicted & actual_in_scope))
            fp = int(np.sum(predicted & ~actual_in_scope))
            fn = int(np.sum(~predicted & actual_in_scope))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            # F-beta with beta=2 (recall weighted 4x)
            beta_sq = 4.0
            f_beta = (
                (1 + beta_sq) * precision * recall / (beta_sq * precision + recall)
                if (precision + recall) > 0
                else 0.0
            )
            if f_beta > best_f_beta:
                best_f_beta = f_beta
                best_threshold = candidate

        if best_threshold <= 0.07 or best_threshold >= 0.83:
            logger.warning(
                "Optimized threshold %.3f is near search boundary - "
                "results may be suboptimal. Consider reviewing your training data.",
                best_threshold,
            )

        logger.info(
            "Threshold optimized: %.3f → %.3f (F2=%.3f, n=%d, iter=%d)",
            scope.threshold,
            best_threshold,
            best_f_beta,
            len(X),
            n_iter,
        )

        # Return new profile with optimized threshold
        return ScopeProfile(
            centroid=scope.centroid,
            topic_embeddings=scope.topic_embeddings,
            topic_labels=scope.topic_labels,
            scope_width="fitted",
            threshold=best_threshold,
            utterance_embeddings=scope.utterance_embeddings,
            utterance_labels=scope.utterance_labels,
            bm25_scorer=scope.bm25_scorer,
            config_hash=scope.config_hash,
        )

    # Threshold calibration

    @staticmethod
    def calibrate_threshold(scope_width: str) -> float:
        """Map scope_width preset to cosine similarity threshold.

        Args:
            scope_width: One of "narrow", "moderate", "broad", "fitted".

        Returns:
            Cosine similarity threshold value.

        Raises:
            ValueError: If scope_width is not recognized.
        """
        if scope_width not in _SCOPE_WIDTH_THRESHOLDS:
            raise ValueError(
                f"Unknown scope_width '{scope_width}'. "
                f"Choose from: {list(_SCOPE_WIDTH_THRESHOLDS.keys())}"
            )
        return _SCOPE_WIDTH_THRESHOLDS[scope_width]
