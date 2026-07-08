# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""ML model lifecycle manager for the in-process LocalRunner.

Loads ML models lazily on first ``Guard()`` use (or eagerly via
``Guard.warmup()``) and caches them as module-level singletons so every
``screen()`` call in the same process shares the same instances.

Models managed:
  - GLiNER (PII detection)
  - TopicScopeEngine (topic scope via sentence-transformers)
  - GroundingEngine (NLI hallucination check - only when
    ``GUARDEX_GROUNDING_ENABLED=1``)

Usage is implicit: ``Guard()`` calls ``LocalRunner._ensure_providers()``
which calls ``load_models()`` once on first screening.  Apps that want
to front-load the download cost should call ``Guard().warmup()`` from
their startup hook.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING

from guardex._engine.settings import local_settings as settings

if TYPE_CHECKING:
    from guardex._engine.ml.topic_scope_engine import TopicScopeEngine

logger = logging.getLogger(__name__)

# Serializes all model loading - concurrent first callers must not
# double-load multi-hundred-MB models into module globals.
_load_lock = threading.RLock()
_models_loaded = False

_gliner_model = None
_semaphore = None
_topic_scope_engine: TopicScopeEngine | None = None


def _load_gliner() -> None:
    """Load GLiNER model for PII detection."""
    global _gliner_model

    try:
        from gliner import GLiNER
        logger.info("Loading GLiNER model '%s'...", settings.gliner_model)
        _gliner_model = GLiNER.from_pretrained(settings.gliner_model)
        logger.info("GLiNER model loaded successfully.")
    except ImportError:
        logger.warning("GLiNER not installed. PII detection will be unavailable.")
    except Exception as e:
        logger.error("Failed to load GLiNER model: %s", e)


def get_gliner_model():
    """Return the cached GLiNER model instance, or None if not loaded."""
    return _gliner_model


def get_semaphore() -> asyncio.Semaphore | None:
    """Return the concurrency semaphore for GLiNER inference."""
    return _semaphore


def load_topic_scope_model() -> None:
    """Load the sentence-transformer model for TopicScope.

    Optional. Logs a warning and returns if sentence-transformers is missing.
    """
    global _topic_scope_engine

    if not settings.topic_scope_enabled:
        logger.info("TopicScope is disabled via config. Skipping model load.")
        return

    try:
        from guardex._engine.ml.topic_scope_engine import TopicScopeEngine

        logger.info("Loading TopicScope engine (model='%s')...", settings.topic_scope_model)
        _topic_scope_engine = TopicScopeEngine(model_name=settings.topic_scope_model)
        logger.info("TopicScope engine loaded successfully.")
    except ImportError:
        logger.warning(
            "sentence-transformers not installed. TopicScope will be unavailable. "
            "Install with: pip install sentence-transformers"
        )
    except Exception as e:
        logger.error("Failed to load TopicScope engine: %s", e)


def get_topic_scope_engine() -> TopicScopeEngine | None:
    """Return the cached TopicScopeEngine instance, or None if not loaded."""
    return _topic_scope_engine


_grounding_engine = None


def load_grounding_engine() -> None:
    """Load the grounding engine for hallucination detection.

    Reuses the sentence-transformer model from TopicScope.
    Optionally loads nli-deberta-v3-base for accuracy mode.
    """
    global _grounding_engine

    if not settings.grounding_enabled:
        logger.info("Grounding is disabled via config. Skipping.")
        return

    try:
        from guardex._engine.ml.grounding.engine import GroundingEngine
        from guardex._engine.ml.grounding.config import GroundingConfig, GroundingMode

        # Reuse the sentence-transformer model from TopicScope if available
        embedding_model = None
        if _topic_scope_engine is not None:
            encoder = _topic_scope_engine._encoder
            # SentenceTransformerEncoder stores the raw model in _model
            raw_model = getattr(encoder, "_model", None) if encoder else None
            if raw_model is None:
                raw_model = getattr(encoder, "_get_model", lambda: None)()
            if raw_model is not None:
                embedding_model = raw_model
                logger.info("Grounding: reusing TopicScope embedding model.")
        else:
            try:
                from sentence_transformers import SentenceTransformer
                embedding_model = SentenceTransformer(settings.topic_scope_model)
                logger.info("Grounding: loaded embedding model '%s'.", settings.topic_scope_model)
            except Exception as e:
                logger.error("Grounding: failed to load embedding model: %s", e)
                return

        # Optionally load NLI cross-encoder for accuracy mode
        nli_model = None
        if settings.grounding_nli_model:
            try:
                from sentence_transformers import CrossEncoder
                logger.info("Grounding: loading NLI model '%s'...", settings.grounding_nli_model)
                nli_model = CrossEncoder(settings.grounding_nli_model)
                logger.info("Grounding: NLI model loaded.")
            except Exception as e:
                logger.warning("Grounding: NLI model not available (%s). Speed mode only.", e)

        config = GroundingConfig(
            mode=GroundingMode(settings.grounding_default_mode),
            grounded_threshold=settings.grounding_threshold,
            faithfulness_pass_threshold=settings.grounding_overall_threshold,
            hybrid_neutral_threshold=settings.grounding_hybrid_neutral_threshold,
        )

        _grounding_engine = GroundingEngine(
            embedding_model=embedding_model,
            nli_model=nli_model,
            config=config,
        )
        logger.info("Grounding engine loaded (mode=%s, nli=%s).",
                     config.mode.value, "yes" if nli_model else "no")

    except ImportError as e:
        logger.warning("Grounding dependencies not installed: %s", e)
    except Exception as e:
        logger.error("Failed to load grounding engine: %s", e)


def get_grounding_engine():
    """Return the grounding engine, loading it on first use if enabled.

    The NLI cross-encoder is ~700 MB; loading it lazily keeps it off the default
    startup path so it only loads for callers that actually use grounding.
    """
    global _grounding_engine
    if _grounding_engine is None and settings.grounding_enabled:
        with _load_lock:
            if _grounding_engine is None:
                load_grounding_engine()
    return _grounding_engine


def load_models() -> None:
    """Load all ML models. Idempotent; safe to call from concurrent threads.

    Grounding is intentionally excluded - its heavy NLI model loads lazily on
    first use via get_grounding_engine().
    """
    global _semaphore, _models_loaded

    with _load_lock:
        if _models_loaded:
            return

        _load_gliner()
        _semaphore = asyncio.Semaphore(settings.gliner_max_concurrency)

        load_topic_scope_model()
        _models_loaded = True
