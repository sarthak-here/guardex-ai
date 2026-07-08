# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Pluggable embedding encoders.

Implement the ``EmbeddingProvider`` protocol to plug in any embedding
model. Built-ins:

- ``SentenceTransformerEncoder`` - local sentence-transformers (default).
- ``OpenAIEncoder`` - OpenAI Embeddings API.
- ``FastEmbedEncoder`` - local ONNX via qdrant/fastembed.
- ``OllamaEncoder`` - local Ollama-hosted embedding models.

Each encoder lazy-imports its dependency, so you only need to install
the one you use.

Usage::

    from guardex.encoders import SentenceTransformerEncoder, OpenAIEncoder

    encoder = SentenceTransformerEncoder()
    encoder = OpenAIEncoder(model="text-embedding-3-small", api_key="sk-...")
    encoder = FastEmbedEncoder(model_name="BAAI/bge-small-en-v1.5")
    encoder = OllamaEncoder(model="nomic-embed-text")
"""

from __future__ import annotations

import logging
import threading
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


def _l2_normalize(arr: np.ndarray) -> np.ndarray:
    """L2-normalize each row vector, safely handling zero-length vectors."""
    norms = np.linalg.norm(arr, axis=1, keepdims=True)
    norms = np.where(norms > 0, norms, 1.0)
    return arr / norms


# Default model constants

DEFAULT_ST_MODEL = "all-MiniLM-L6-v2"
DEFAULT_OPENAI_MODEL = "text-embedding-3-small"
DEFAULT_FASTEMBED_MODEL = "BAAI/bge-small-en-v1.5"
DEFAULT_OLLAMA_MODEL = "nomic-embed-text"
DEFAULT_OLLAMA_URL = "http://localhost:11434"


# Sentence-Transformer encoder (default)


class SentenceTransformerEncoder:
    """Local sentence-transformers encoder. Default for GuardEx.

    Parameters
    ----------
    model_name : str
        HuggingFace model identifier. Default ``all-MiniLM-L6-v2`` (22 MB, 384-dim).
    """

    def __init__(self, model_name: str = DEFAULT_ST_MODEL) -> None:
        self._model_name = model_name
        self._model: Any | None = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return f"sentence-transformer:{self._model_name}"

    @property
    def dimensions(self) -> int:
        return self._get_model().get_sentence_embedding_dimension()

    def _get_model(self) -> Any:
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise ImportError(
                    "sentence-transformers is required for SentenceTransformerEncoder. "
                    "Install with: pip install sentence-transformers"
                ) from exc
            logger.info("Loading sentence-transformer model '%s'...", self._model_name)
            self._model = SentenceTransformer(self._model_name)
            logger.info(
                "Model loaded: %s (dim=%d)",
                self._model_name,
                self._model.get_sentence_embedding_dimension(),
            )
            return self._model

    def encode(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """Encode texts to dense vectors.

        Returns:
            np.ndarray of shape (N, dimensions) with L2-normalized rows.
        """
        model = self._get_model()
        embeddings: np.ndarray = model.encode(
            texts,
            normalize_embeddings=normalize,
            show_progress_bar=False,
        )
        return embeddings.astype(np.float32)


# OpenAI encoder


class OpenAIEncoder:
    """OpenAI Embeddings API encoder.

    Parameters
    ----------
    model : str
        Model identifier. Default ``text-embedding-3-small`` (1536-dim).
    api_key : str | None
        OpenAI API key. Falls back to ``OPENAI_API_KEY`` env var.
    base_url : str | None
        Custom base URL for OpenAI-compatible APIs (e.g., Azure, local proxies).
    max_retries : int
        Maximum retry attempts for transient errors.
    """

    # Known dimensions per model - avoids a test API call to discover dims.
    _MODEL_DIMS: dict[str, int] = {
        "text-embedding-3-small": 1536,
        "text-embedding-3-large": 3072,
        "text-embedding-ada-002": 1536,
    }

    def __init__(
        self,
        model: str = DEFAULT_OPENAI_MODEL,
        api_key: str | None = None,
        base_url: str | None = None,
        max_retries: int = 3,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._base_url = base_url
        self._max_retries = max_retries
        self._client: Any | None = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return f"openai:{self._model}"

    @property
    def dimensions(self) -> int:
        return self._MODEL_DIMS.get(self._model, 1536)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        with self._lock:
            if self._client is not None:
                return self._client
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise ImportError(
                    "openai is required for OpenAIEncoder. "
                    "Install with: pip install openai"
                ) from exc
            kwargs: dict[str, Any] = {"max_retries": self._max_retries}
            if self._api_key:
                kwargs["api_key"] = self._api_key
            if self._base_url:
                kwargs["base_url"] = self._base_url
            self._client = OpenAI(**kwargs)
            return self._client

    def encode(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """Encode texts via OpenAI Embeddings API.

        Returns:
            np.ndarray of shape (N, dimensions).
        """
        client = self._get_client()
        response = client.embeddings.create(model=self._model, input=texts)
        vectors = [item.embedding for item in response.data]
        result = np.array(vectors, dtype=np.float32)
        if normalize:
            result = _l2_normalize(result)
        return result


# FastEmbed encoder


class FastEmbedEncoder:
    """Local ONNX-based encoder via qdrant/fastembed.

    Parameters
    ----------
    model_name : str
        Model identifier. Default ``BAAI/bge-small-en-v1.5`` (384-dim).
    threads : int | None
        Number of ONNX inference threads. None = auto.
    """

    _MODEL_DIMS: dict[str, int] = {
        "BAAI/bge-small-en-v1.5": 384,
        "BAAI/bge-base-en-v1.5": 768,
        "sentence-transformers/all-MiniLM-L6-v2": 384,
    }

    def __init__(
        self,
        model_name: str = DEFAULT_FASTEMBED_MODEL,
        threads: int | None = None,
    ) -> None:
        self._model_name = model_name
        self._threads = threads
        self._model: Any | None = None
        self._lock = threading.Lock()

    @property
    def name(self) -> str:
        return f"fastembed:{self._model_name}"

    @property
    def dimensions(self) -> int:
        return self._MODEL_DIMS.get(self._model_name, 384)

    def _get_model(self) -> Any:
        if self._model is not None:
            return self._model
        with self._lock:
            if self._model is not None:
                return self._model
            try:
                from fastembed import TextEmbedding
            except ImportError as exc:
                raise ImportError(
                    "fastembed is required for FastEmbedEncoder. "
                    "Install with: pip install fastembed"
                ) from exc
            kwargs: dict[str, Any] = {"model_name": self._model_name}
            if self._threads is not None:
                kwargs["threads"] = self._threads
            logger.info("Loading FastEmbed model '%s'...", self._model_name)
            self._model = TextEmbedding(**kwargs)
            logger.info("FastEmbed model loaded: %s", self._model_name)
            return self._model

    def encode(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """Encode texts via FastEmbed ONNX runtime.

        Returns:
            np.ndarray of shape (N, dimensions).
        """
        model = self._get_model()
        # FastEmbed returns a generator - consume into array
        embeddings_list = list(model.embed(texts))
        result = np.array(embeddings_list, dtype=np.float32)
        if normalize:
            result = _l2_normalize(result)
        return result


# Ollama encoder


class OllamaEncoder:
    """Local Ollama-hosted embedding model encoder.

    Parameters
    ----------
    model : str
        Ollama model name. Default ``nomic-embed-text``.
    base_url : str
        Ollama server URL. Default ``http://localhost:11434``.
    """

    def __init__(
        self,
        model: str = DEFAULT_OLLAMA_MODEL,
        base_url: str = DEFAULT_OLLAMA_URL,
    ) -> None:
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._dimensions: int | None = None

    @property
    def name(self) -> str:
        return f"ollama:{self._model}"

    @property
    def dimensions(self) -> int:
        if self._dimensions is not None:
            return self._dimensions
        # Discover dimensions by embedding a single token
        vec = self._embed_single("test")
        self._dimensions = len(vec)
        return self._dimensions

    def _embed_single(self, text: str) -> list[float]:
        """Embed a single text string via Ollama API."""
        try:
            import httpx
        except ImportError as exc:
            raise ImportError(
                "httpx is required for OllamaEncoder. "
                "Install with: pip install httpx"
            ) from exc
        response = httpx.post(
            f"{self._base_url}/api/embeddings",
            json={"model": self._model, "prompt": text},
            timeout=60.0,
        )
        response.raise_for_status()
        return response.json()["embedding"]

    def encode(self, texts: list[str], normalize: bool = True) -> np.ndarray:
        """Encode texts via Ollama embeddings API.

        Note: Ollama's /api/embeddings processes one text at a time.
        For batches, we make sequential calls.

        Returns:
            np.ndarray of shape (N, dimensions).
        """
        vectors = [self._embed_single(text) for text in texts]
        result = np.array(vectors, dtype=np.float32)
        if normalize:
            result = _l2_normalize(result)
        return result


# Encoder factory


_ENCODER_REGISTRY: dict[str, type] = {
    "sentence-transformer": SentenceTransformerEncoder,
    "openai": OpenAIEncoder,
    "fastembed": FastEmbedEncoder,
    "ollama": OllamaEncoder,
}


def create_encoder(encoder_type: str, **kwargs: Any) -> Any:
    """Factory function to create an encoder by type name.

    Parameters
    ----------
    encoder_type : str
        One of: "sentence-transformer", "openai", "fastembed", "ollama".
    **kwargs
        Passed to the encoder constructor.

    Returns:
        An encoder instance satisfying the EmbeddingProvider protocol.

    Raises:
        ValueError: If encoder_type is not recognized.

    Example::

        encoder = create_encoder("openai", model="text-embedding-3-large", api_key="sk-...")
        encoder = create_encoder("fastembed", model_name="BAAI/bge-base-en-v1.5")
    """
    cls = _ENCODER_REGISTRY.get(encoder_type)
    if cls is None:
        raise ValueError(
            f"Unknown encoder type '{encoder_type}'. "
            f"Available: {list(_ENCODER_REGISTRY.keys())}"
        )
    return cls(**kwargs)
