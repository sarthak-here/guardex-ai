# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""ONNX-based safety classifier provider.

Implements the ClassifierProvider protocol using the OnnxSafetyEngine.
This is the high-performance alternative to LlamaGuard via Ollama:
  - Ollama (generative, 1B params): 500-2000ms per request
  - ONNX (encoder, ~86M params): 10-50ms per request

The provider wraps the synchronous ONNX engine in asyncio.to_thread()
to avoid blocking the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class OnnxClassifierProvider:
    """Safety classifier using ONNX Runtime.

    Parameters
    ----------
    model_path:
        Path to the ONNX model file (.onnx).
    tokenizer_path:
        Path to the HuggingFace tokenizer directory.
    label_map:
        Mapping from model output index to label string.
    category_map:
        Optional mapping from model label to GuardEx S-code.
    max_length:
        Maximum token sequence length.
    unsafe_threshold:
        Probability threshold for flagging a category.
    num_threads:
        ONNX Runtime intra-op thread count.
    use_gpu:
        Use CUDA execution provider if available.
    use_int8:
        If True and model_path doesn't end with '_int8.onnx',
        look for a quantized variant alongside the model file.
    """

    name: str = "guardex-shield-onnx-v1"

    def __init__(
        self,
        model_path: str,
        tokenizer_path: str,
        label_map: dict[int, str] | None = None,
        category_map: dict[str, str] | None = None,
        max_length: int = 512,
        unsafe_threshold: float = 0.5,
        num_threads: int = 4,
        use_gpu: bool = False,
        use_int8: bool = True,
    ) -> None:
        # Auto-detect INT8 model if requested
        actual_model_path = model_path
        if use_int8:
            int8_path = _find_int8_model(model_path)
            if int8_path:
                actual_model_path = int8_path
                logger.info("Using INT8 quantized model: %s", int8_path)

        # Auto-load label map from JSON if present
        if label_map is None:
            label_map = _load_label_map(tokenizer_path)

        from guardex._engine.ml.onnx_engine import OnnxSafetyEngine

        self._engine = OnnxSafetyEngine(
            model_path=actual_model_path,
            tokenizer_path=tokenizer_path,
            label_map=label_map,
            category_map=category_map,
            max_length=max_length,
            unsafe_threshold=unsafe_threshold,
            num_threads=num_threads,
            use_gpu=use_gpu,
        )

    async def classify(
        self,
        text: str,
        stage: str = "input",
        categories: list[str] | None = None,
        **_extra: Any,
    ) -> dict[str, Any]:
        """Classify text for safety using ONNX inference.

        Runs in a thread pool to avoid blocking the async event loop.
        ONNX Runtime sessions are thread-safe.
        """
        return await asyncio.to_thread(
            self._engine.classify, text, stage, categories,
        )


def _find_int8_model(model_path: str) -> str | None:
    """Look for an INT8 quantized variant of the model."""
    path = Path(model_path)

    # Already an INT8 model
    if "_int8" in path.stem:
        if path.exists():
            return model_path
        return None

    # Look for model_int8.onnx alongside model.onnx
    int8_path = path.parent / f"{path.stem}_int8{path.suffix}"
    if int8_path.exists():
        return str(int8_path)

    return None


def _load_label_map(tokenizer_path: str) -> dict[int, str] | None:
    """Try to load label_map.json from the tokenizer/model directory."""
    label_map_path = Path(tokenizer_path) / "label_map.json"
    if label_map_path.exists():
        with open(label_map_path) as f:
            raw = json.load(f)
        # JSON keys are strings - convert to int
        return {int(k): v for k, v in raw.items()}
    return None
