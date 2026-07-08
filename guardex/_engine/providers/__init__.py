# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Provider system initialization.

``init_providers()`` is the single entry point, called by
``LocalRunner._ensure_providers``.  It loads ML models first, then
registers the provider adapters that wrap them.
"""

import logging

from guardex._engine.providers.registry import (
    register_pii_provider,
    register_classifier_provider,
    register_topic_scope_provider,
)

logger = logging.getLogger(__name__)


def init_providers() -> None:
    """Load all ML models and register their providers."""
    from guardex._engine.ml.model_manager import load_models
    from guardex._engine.providers.gliner_provider import GlinerPiiProvider
    from guardex._engine.providers.llamaguard_provider import LlamaGuardClassifierProvider

    load_models()

    register_pii_provider(GlinerPiiProvider())
    register_classifier_provider(LlamaGuardClassifierProvider())

    # Register ONNX classifier if enabled and configured
    _init_onnx_classifier()

    # Register cascade classifier if enabled (requires ONNX + LlamaGuard)
    _init_cascade_classifier()

    # Register topic scope provider if enabled
    _init_topic_scope()

    # Register grounding provider if enabled
    _init_grounding()


def _download_onnx_model(repo_id: str, use_int8: bool) -> tuple[str, str]:
    """Download ONNX model + tokenizer from HuggingFace Hub.

    Returns (model_path, tokenizer_dir). Files are cached by huggingface_hub
    so subsequent calls are instant.
    """
    from huggingface_hub import hf_hub_download, snapshot_download

    model_filename = "model_int8.onnx" if use_int8 else "model.onnx"

    logger.info(
        "Downloading ONNX model from HuggingFace: %s/%s ...",
        repo_id, model_filename,
    )
    model_path = hf_hub_download(repo_id=repo_id, filename=model_filename)

    # Download the full repo snapshot for tokenizer files (config, vocab, merges, etc.)
    tokenizer_dir = snapshot_download(
        repo_id=repo_id,
        ignore_patterns=["*.onnx"],  # skip large model files, only get tokenizer
    )

    logger.info("ONNX model downloaded: %s", model_path)
    return model_path, tokenizer_dir


def _init_onnx_classifier() -> None:
    """Register the ONNX safety classifier provider if configured.

    If onnx_model_path is empty but onnx_classifier_enabled=True,
    auto-downloads the model from HuggingFace Hub.
    """
    from guardex._engine.settings import local_settings as settings

    if not settings.onnx_classifier_enabled:
        return

    model_path = settings.onnx_model_path
    tokenizer_path = settings.onnx_tokenizer_path

    # Auto-download from HuggingFace if no local path is set
    if not model_path:
        try:
            model_path, tokenizer_path = _download_onnx_model(
                repo_id=settings.onnx_hf_repo,
                use_int8=settings.onnx_use_int8,
            )
        except ImportError:
            logger.warning(
                "ONNX auto-download requires huggingface_hub. "
                "Install with: pip install huggingface_hub  "
                "Or set GUARDEX_ONNX_MODEL_PATH to a local file."
            )
            return
        except Exception as e:
            logger.error("Failed to download ONNX model from HuggingFace: %s", e)
            return

    try:
        from guardex._engine.providers.onnx_provider import OnnxClassifierProvider

        provider = OnnxClassifierProvider(
            model_path=model_path,
            tokenizer_path=tokenizer_path or model_path,
            max_length=settings.onnx_max_length,
            unsafe_threshold=settings.onnx_unsafe_threshold,
            num_threads=settings.onnx_num_threads,
            use_gpu=settings.onnx_use_gpu,
            use_int8=settings.onnx_use_int8,
        )
        register_classifier_provider(provider)
        logger.info(
            "ONNX classifier registered: %s (INT8=%s, GPU=%s)",
            model_path,
            settings.onnx_use_int8,
            settings.onnx_use_gpu,
        )
    except ImportError as e:
        logger.warning(
            "ONNX classifier enabled but dependencies missing: %s. "
            "Install with: pip install onnxruntime transformers",
            e,
        )
    except Exception as e:
        logger.error("Failed to initialize ONNX classifier: %s", e)


def _init_cascade_classifier() -> None:
    """Register cascade classifier if both ONNX and LlamaGuard are available."""
    from guardex._engine.settings import local_settings as settings
    from guardex._engine.providers.registry import get_classifier_provider

    if not settings.cascade_enabled:
        return

    if not settings.onnx_classifier_enabled:
        logger.warning(
            "Cascade enabled but ONNX classifier not enabled. "
            "Set GUARDEX_ONNX_CLASSIFIER_ENABLED=true first."
        )
        return

    try:
        # Get the ONNX provider's engine (fast path)
        onnx_provider = get_classifier_provider("guardex-shield-onnx-v1")
        if onnx_provider is None:
            logger.warning("Cascade enabled but ONNX provider not registered. Skipping.")
            return

        # Get the LlamaGuard provider (slow path / fallback)
        llamaguard_provider = get_classifier_provider("guardex-shield-v1")
        if llamaguard_provider is None:
            logger.warning("Cascade enabled but LlamaGuard provider not registered. Skipping.")
            return

        from guardex._engine.providers.cascade_provider import CascadeClassifierProvider

        cascade = CascadeClassifierProvider(
            fast_engine=onnx_provider._engine,
            slow_provider=llamaguard_provider,
            safe_threshold=settings.cascade_safe_threshold,
            unsafe_threshold=settings.cascade_unsafe_threshold,
            mode=settings.cascade_mode,
            normalize=settings.text_normalization_enabled,
            keyword_gate=settings.keyword_gate_enabled,
            fail_open=settings.fail_open,
        )
        register_classifier_provider(cascade)
        logger.info(
            "Cascade classifier registered: mode=%s, safe<%.2f, unsafe>%.2f",
            settings.cascade_mode,
            settings.cascade_safe_threshold,
            settings.cascade_unsafe_threshold,
        )
    except Exception as e:
        logger.error("Failed to initialize cascade classifier: %s", e)


def _init_topic_scope() -> None:
    """Register topic scope provider if the ML engine is available."""
    try:
        from guardex._engine.ml.model_manager import get_topic_scope_engine

        engine = get_topic_scope_engine()
        if engine is None:
            logger.info("Topic scope engine not available. Skipping scope provider.")
            return

        from guardex._engine.providers.topic_scope_provider import SentenceTransformerScopeProvider

        provider = SentenceTransformerScopeProvider(engine=engine)
        register_topic_scope_provider(provider)
        logger.info("Topic scope provider registered: %s", provider.name)
    except ImportError as e:
        logger.info(
            "Topic scope engine not installed (expected if feature not enabled): %s", e,
        )
    except Exception as e:
        logger.error("Failed to initialize topic scope provider: %s", e)


def _init_grounding() -> None:
    """Register grounding provider if the ML engine is available."""
    try:
        from guardex._engine.ml.model_manager import get_grounding_engine

        engine = get_grounding_engine()
        if engine is None:
            logger.info("Grounding engine not available. Skipping grounding provider.")
            return

        from guardex._engine.providers.grounding_provider import GroundingProvider
        from guardex._engine.providers.registry import register_grounding_provider

        provider = GroundingProvider(engine=engine)
        register_grounding_provider(provider)
        logger.info("Grounding provider registered: %s", provider.name)
    except ImportError as e:
        logger.info("Grounding engine not installed: %s", e)
    except Exception as e:
        logger.error("Failed to initialize grounding provider: %s", e)

