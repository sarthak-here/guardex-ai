# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Provider registry -- resolves provider instances by name.

Built-in providers are registered by ``init_providers()`` on first use.
"""

from __future__ import annotations

import logging

import threading

from guardex._engine.providers.base import PiiProvider, ClassifierProvider, TopicScopeProvider

logger = logging.getLogger(__name__)

# Module-level registries - protected by a single lock for thread safety
_registry_lock = threading.Lock()
_pii_providers: dict[str, PiiProvider] = {}
_classifier_providers: dict[str, ClassifierProvider] = {}


# -- Registration --

def register_pii_provider(provider: PiiProvider) -> None:
    with _registry_lock:
        if provider.name in _pii_providers:
            logger.warning(
                "PII provider '%s' already registered - overwriting. "
                "If unintentional, check for duplicate init_providers() calls.",
                provider.name,
            )
        _pii_providers[provider.name] = provider
    logger.info("Registered PII provider: %s", provider.name)


def register_classifier_provider(provider: ClassifierProvider) -> None:
    with _registry_lock:
        if provider.name in _classifier_providers:
            logger.warning(
                "Classifier provider '%s' already registered - overwriting. "
                "If unintentional, check for duplicate init_providers() calls.",
                provider.name,
            )
        _classifier_providers[provider.name] = provider
    logger.info("Registered classifier provider: %s", provider.name)


# -- Resolution --

def get_pii_provider(name: str | None = None) -> PiiProvider | None:
    with _registry_lock:
        if name is None or name == "":
            name = "guardex-pii-v1"
        return _pii_providers.get(name)


def get_classifier_provider(name: str | None = None) -> ClassifierProvider | None:
    with _registry_lock:
        if not name:
            # Prefer cascade > ONNX > first available
            cascade = _classifier_providers.get("guardex-shield-cascade-v1")
            if cascade is not None:
                return cascade
            onnx = _classifier_providers.get("guardex-shield-onnx-v1")
            if onnx is not None:
                return onnx
            # Try legacy name, then fall back to first registered classifier
            if "guardex-shield-v1" in _classifier_providers:
                return _classifier_providers["guardex-shield-v1"]
            if _classifier_providers:
                return next(iter(_classifier_providers.values()))
            return None
        return _classifier_providers.get(name)


def unregister_classifier_provider(name: str) -> None:
    with _registry_lock:
        if name in _classifier_providers:
            del _classifier_providers[name]
    logger.info("Unregistered classifier provider: %s", name)


def unregister_pii_provider(name: str) -> None:
    """Remove a PII provider from the registry by name."""
    with _registry_lock:
        if name in _pii_providers:
            del _pii_providers[name]
    logger.info("Unregistered PII provider: %s", name)


def list_pii_providers() -> list[str]:
    with _registry_lock:
        return list(_pii_providers.keys())


def list_classifier_providers() -> list[str]:
    with _registry_lock:
        return list(_classifier_providers.keys())


# -- Topic Scope Provider --

_topic_scope_provider: TopicScopeProvider | None = None


def register_topic_scope_provider(provider: TopicScopeProvider) -> None:
    global _topic_scope_provider
    with _registry_lock:
        _topic_scope_provider = provider
    logger.info("Registered topic scope provider: %s", provider.name)


def get_topic_scope_provider() -> TopicScopeProvider | None:
    with _registry_lock:
        return _topic_scope_provider


# -- Grounding Provider --

_grounding_provider = None


def register_grounding_provider(provider) -> None:
    global _grounding_provider
    with _registry_lock:
        _grounding_provider = provider
    logger.info("Registered grounding provider: %s", provider.name)


def get_grounding_provider():
    with _registry_lock:
        return _grounding_provider
