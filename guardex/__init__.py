# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""GuardEx SDK - AI guardrails for any LLM application.

Quick start (zero-config local mode, runs fully in-process)::

    from guardex import Guard

    guard = Guard()
    result = guard.screen("user input", gate="input")
    if result.blocked:
        print(f"Blocked: {result.classify.category}")

Server mode (point at a self-hosted GuardEx server)::

    guard = Guard(base_url="http://localhost:8001")

Async usage::

    async with Guard() as guard:
        result = await guard.ascreen("Hello", gate="input")

Context-aware screening::

    from guardex import Guard, GuardExContext, DeploymentContext, UserContext, Region

    ctx = GuardExContext(
        deployment=DeploymentContext.PRODUCTION,
        user=UserContext(region=Region.EU),
    )
    result = guard.screen("user input", gate="input", context=ctx)

Batch screening::

    results = guard.screen_batch(["text1", "text2", "text3"], gate="input")

PII vault::

    from guardex import PIIVault

    vault = PIIVault()
    vaulted_text, _ = vault.vault_text(text, pii_result)
    # vault is populated in place - vaulted_text contains {{pii:...}}
    # tokens that map back to the originals via vault.restore().
    llm_reply = call_llm(vaulted_text)
    final_reply = vault.restore(llm_reply)
"""

from ._version import get_package_version as _get_version
from ._types import (
    Action,
    ClassifyResult,
    CATEGORY_DESCRIPTIONS,
    CATEGORY_ALIASES,
    CATEGORY_CODE_TO_NAME,
    DEFAULT_BLOCKED,
    Gate,
    GateTrace,
    GroundingResult,
    SentenceGroundingResult,
    PIIEntity,
    PIIResult,
    ScopeResult,
    SafetyRouteOutcome,
    ScreenResult,
    resolve_category,
    resolve_categories,
)
from .stream import AsyncStreamGuard, StreamGuard
from .async_client import AsyncGuardExClient
from .classifier import LlamaGuardClassifier
from .client import GuardExClient
from .effective_config import EffectiveConfig, PIIMergedConfig, ContentMergedConfig
from .exceptions import GuardExAPIError, GuardExViolation, PIIViolation
from .guard import Guard
from .handler import GuardExCallbackHandler
from .policy import (
    ALL_CATEGORIES,
    ALL_PII_ENTITIES,
    DEFAULT_PII_ENTITIES,
    GuardExPolicy,
    TopicScope,
)
from .wrapper import GuardedLLM
from .context import (
    GuardExContext,
    DeploymentContext,
    UserContext,
    RequestContext,
    AuthStatus,
    UserRole,
    Region,
    Industry,
    RequestType,
)
from .policy_override import PolicyOverride
from .policy_resolver import resolve_policy, CachedPolicyResolver

from .pii_vault import PIIVault, VaultEntry
from .injection import InjectionDetector, InjectionResult, InjectionMatch
from .conversation import ConversationGuard, Turn
from .telemetry import otel_available
# Encoder and safety-route classes are lazy-loaded to avoid pulling in numpy
# at import time for users who only need Guard + API mode (server-side).
# Direct imports still work: ``from guardex.encoders import ...``

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "SentenceTransformerEncoder": (".encoders", "SentenceTransformerEncoder"),
    "OpenAIEncoder": (".encoders", "OpenAIEncoder"),
    "FastEmbedEncoder": (".encoders", "FastEmbedEncoder"),
    "OllamaEncoder": (".encoders", "OllamaEncoder"),
    "create_encoder": (".encoders", "create_encoder"),
    "SafetyRoute": (".safety_route", "SafetyRoute"),
    "SafetyRouteResult": (".safety_route", "SafetyRouteResult"),
    "SafetyRouteEngine": (".safety_route", "SafetyRouteEngine"),
    "EmbeddingProvider": ("._engine.providers.base", "EmbeddingProvider"),
}


def __getattr__(name: str):
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        import importlib
        mod = importlib.import_module(module_path, __name__)
        val = getattr(mod, attr)
        globals()[name] = val  # cache so __getattr__ isn't called again
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Main integration classes
    "Guard",
    "GuardedLLM",
    "GuardExCallbackHandler",
    # HTTP clients
    "GuardExClient",
    "AsyncGuardExClient",
    # Streaming
    "StreamGuard",
    "AsyncStreamGuard",
    # Direct safety classifier
    "LlamaGuardClassifier",
    # Config
    "GuardExPolicy",
    "TopicScope",
    "ALL_CATEGORIES",
    "ALL_PII_ENTITIES",
    "DEFAULT_BLOCKED",
    "DEFAULT_PII_ENTITIES",
    "CATEGORY_DESCRIPTIONS",
    "CATEGORY_ALIASES",
    "CATEGORY_CODE_TO_NAME",
    # Type aliases
    "Gate",
    "Action",
    # Result types
    "ClassifyResult",
    "GateTrace",
    "GroundingResult",
    "SentenceGroundingResult",
    "PIIEntity",
    "PIIResult",
    "ScopeResult",
    "SafetyRouteOutcome",
    "ScreenResult",
    # Category helpers
    "resolve_category",
    "resolve_categories",
    # Effective config
    "EffectiveConfig",
    "PIIMergedConfig",
    "ContentMergedConfig",
    # Exceptions
    "GuardExViolation",
    "PIIViolation",
    "GuardExAPIError",
    # Context
    "GuardExContext",
    "DeploymentContext",
    "UserContext",
    "RequestContext",
    "AuthStatus",
    "UserRole",
    "Region",
    "Industry",
    "RequestType",
    "PolicyOverride",
    "resolve_policy",
    "CachedPolicyResolver",
    # PII vault
    "PIIVault",
    "VaultEntry",
    # Injection detection
    "InjectionDetector",
    "InjectionResult",
    "InjectionMatch",
    # Multi-turn
    "ConversationGuard",
    "Turn",
    # Telemetry
    "otel_available",
    # Encoders
    "EmbeddingProvider",
    "SentenceTransformerEncoder",
    "OpenAIEncoder",
    "FastEmbedEncoder",
    "OllamaEncoder",
    "create_encoder",
    # Safety routes
    "SafetyRoute",
    "SafetyRouteResult",
    "SafetyRouteEngine",
]

__version__ = _get_version()
