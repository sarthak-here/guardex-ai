# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Guard - primary entry point for screening text at any gate.

Framework-agnostic. Works with any LLM, any framework, any architecture.

Quick start (zero-config local mode)::

    from guardex import Guard

    guard = Guard()
    result = guard.screen("user input", gate="input")
    if result.blocked:
        print(f"Blocked: {result.classify.category}")

Server mode (self-hosted GuardEx server)::

    guard = Guard(base_url="http://localhost:8001")

Context-aware screening::

    from guardex import Guard, GuardExContext, DeploymentContext, UserContext, Region, Industry

    guard = Guard()
    ctx = GuardExContext(
        deployment=DeploymentContext.PRODUCTION,
        user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
    )
    result = guard.screen("patient data", gate="input", context=ctx)

Wrap any callable::

    safe_fn = guard.wrap(my_tool, gate="tool_input")

Stream screening::

    for chunk in guard.stream(llm_stream, gate="output"):
        print(chunk, end="")
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import logging
import os
from pathlib import Path
from typing import Any, Callable, Iterator, AsyncIterator, List, TypeVar

from .client import GuardExClient
from .async_client import AsyncGuardExClient
from .policy import GuardExPolicy
from .policy_resolver import CachedPolicyResolver
from .context import GuardExContext
from .injection import InjectionDetector
from .telemetry import screening_span, record_result, emit_audit_log
from ._types import (
    Gate, ScreenResult, ClassifyResult, PIIResult, PIIEntity,
    ScopeResult, Action, GateTrace, gate_to_stage, output_gate_for,
)
from .exceptions import GuardExViolation

logger = logging.getLogger(__name__)

# Warn at most once per process when blocked_categories can't be honored locally.
_WARNED_BLOCKED_CATEGORIES_INERT = False

T = TypeVar("T")

# Gates that correspond to "input" for policy flag checks
_INPUT_GATES = frozenset({"input", "prompt", "tool_input", "retrieval_query"})


def _probe_ollama(url: str, model: str, timeout: float = 0.5) -> bool:
    """Return True only if the Ollama daemon at *url* has *model* pulled.

    Strict probe: a 200 ``/api/tags`` JSON payload whose ``models`` list
    contains the configured model is required.  A reachable Ollama without
    the model would make every cascade escalation fail closed and block
    benign text - common when Ollama is installed for unrelated models.
    Any other HTTP server bound to the same port (corporate proxy, dev
    tools) also fails this check.
    """
    try:
        import httpx  # already a hard dependency
        r = httpx.get(f"{url.rstrip('/')}/api/tags", timeout=timeout)
        if r.status_code != 200:
            return False
        if not r.headers.get("content-type", "").startswith("application/json"):
            return False
        models = r.json().get("models")
        if not isinstance(models, list):
            return False
        # Ollama names carry tags ("llama-guard3:1b"); match either exactly
        # or by base name when the configured value has no tag.
        wanted = model.lower()
        for m in models:
            name = str(m.get("name", "")).lower()
            if name == wanted or name.split(":")[0] == wanted:
                return True
        return False
    except Exception:
        return False


def _parse_grounding_result(
    raw: dict,
    request_id: str | None = None,
) -> "GroundingResult":
    """Convert raw API response into a typed GroundingResult."""
    from ._types import GroundingResult, SentenceGroundingResult

    details = [
        SentenceGroundingResult(
            sentence=s.get("sentence", ""),
            grounded=s.get("grounded", True),
            score=s.get("entailment", s.get("score", 1.0)),
            matched_chunk=s.get("matched_chunk"),
            verdict=s.get("verdict", "grounded"),
            contradiction=s.get("contradiction", 0.0),
            neutral=s.get("neutral", 0.0),
        )
        for s in raw.get("details", [])
    ]

    return GroundingResult(
        grounded=raw.get("grounded", True),
        faithfulness_score=raw.get("faithfulness_score", 1.0),
        has_contradiction=raw.get("has_contradiction", False),
        sentence_count=raw.get("sentence_count", 0),
        grounded_count=raw.get("grounded_count", 0),
        contradicted_count=raw.get("contradicted_count", 0),
        ungrounded_count=raw.get("ungrounded_count", 0),
        uncertain_count=raw.get("uncertain_count", 0),
        details=details,
        mode=raw.get("mode", "accuracy"),
        latency_ms=raw.get("latency_ms", 0.0),
        request_id=request_id,
    )


def _parse_screen_result(
    raw: dict,
    gate: str,
    original_text: str,
    request_id: str | None = None,
    min_confidence: float = 0.0,
    pii_action: str = "mask",
) -> ScreenResult:
    """Convert raw API response dict into a typed ScreenResult."""
    # Pull diagnostics first so they survive every early-return below.
    diag_payload = raw.get("_diagnostics") or []
    diagnostics_t: tuple[GateTrace, ...] = tuple(
        GateTrace(
            gate=d.get("gate", ""),
            ran=bool(d.get("ran", False)),
            skipped_reason=d.get("skipped_reason"),
            duration_ms=float(d.get("duration_ms", 0.0)),
            blocked=bool(d.get("blocked", False)),
            note=d.get("note"),
        )
        for d in diag_payload
        if isinstance(d, dict)
    )
    gates_run_t: tuple[str, ...] = tuple(t.gate for t in diagnostics_t if t.ran)

    # Handle fail-open responses
    if raw.get("_fail_open"):
        logger.error(
            "GuardEx screening FAILED OPEN: content passed WITHOUT screening. "
            "This is not a real safety verdict (request_id=%s).", request_id
        )
        return ScreenResult(
            gate=gate,
            action="pass",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text=original_text,
            request_id=request_id,
            gates_run=gates_run_t,
            diagnostics=diagnostics_t,
            degraded=True,
        )

    # Parse classification
    clf_data = raw.get("classify", {})
    classify = ClassifyResult(
        safe=clf_data.get("safe", True),
        category=clf_data.get("category"),
        categories=clf_data.get("categories", []),
        confidence=clf_data.get("confidence", 1.0),
        description=clf_data.get("description"),
    )

    # Parse PII
    pii_data = raw.get("pii", {})
    pii_entities = [
        PIIEntity(
            text=e.get("text", ""),
            label=e.get("label", ""),
            score=e.get("score", 0.0),
            start=e.get("start", 0),
            end=e.get("end", 0),
        )
        for e in pii_data.get("entities", [])
    ]
    pii = PIIResult(
        has_pii=pii_data.get("has_pii", False),
        entities=pii_entities,
        masked_text=pii_data.get("masked_text"),
    )

    # Parse scope
    scope = None
    scope_data = raw.get("scope")
    if scope_data is not None:
        scope = ScopeResult(
            allowed=scope_data.get("allowed", True),
            distance=scope_data.get("distance", 0.0),
            matched_topic=scope_data.get("matched_topic"),
            confidence=scope_data.get("confidence", 1.0),
            reason=scope_data.get("reason"),
        )

    # If confidence is below the threshold, treat as safe to reduce false positives.
    # Controlled by policy.classify_min_confidence.
    if min_confidence > 0.0 and not classify.safe and classify.confidence < min_confidence:
        logger.debug(
            "GuardEx min_confidence override: confidence=%.3f < threshold=%.3f, "
            "overriding %s to safe",
            classify.confidence, min_confidence, classify.category,
        )
        classify = ClassifyResult(
            safe=True,
            category=classify.category,
            categories=classify.categories,
            confidence=classify.confidence,
            description=f"[overridden: confidence {classify.confidence:.3f} < {min_confidence:.3f}]",
        )

    # Determine action
    text = raw.get("text", original_text)
    if scope and not scope.allowed:
        action: Action = "block"
    elif not classify.safe:
        action = "block"
    elif pii.has_pii and pii_action == "block":
        action = "block"
    elif pii.has_pii and pii.masked_text:
        action = "mask"
    else:
        action = "pass"

    return ScreenResult(
        gate=gate,
        action=action,
        classify=classify,
        pii=pii,
        text=text,
        scope=scope,
        request_id=request_id,
        gates_run=gates_run_t,
        diagnostics=diagnostics_t,
    )


def _enforce_block(result: ScreenResult, gate: str, policy: GuardExPolicy) -> bool:
    """Whether a blocked ScreenResult must be enforced (raise / stop).

    ``block_on_unsafe_input`` and ``block_on_unsafe_output`` govern the
    safety-classifier verdict only. Prompt injection, topic scope, safety
    routes, and ``pii_action="block"`` are independent controls that always
    enforce, so observe-only mode never silently disables them.
    """
    if result.classify.category == "injection":
        return True
    if result.scope is not None and not result.scope.allowed:
        return True
    sr = result.safety_route
    if sr is not None and sr.matched and sr.action == "block":
        return True
    if policy.pii_enabled and policy.pii_action == "block" and result.pii.has_pii:
        return True
    if gate in _INPUT_GATES:
        return policy.block_on_unsafe_input
    return policy.block_on_unsafe_output


def _block_category(result: ScreenResult) -> str | None:
    """Best category label for a blocked result's GuardExViolation.

    The safety classifier populates ``classify.category``; scope and safety
    routes do not, so fall back to a source label matching what GuardedLLM
    and the callback handler raise.
    """
    if result.classify.category:
        return result.classify.category
    if result.scope is not None and not result.scope.allowed:
        return "scope"
    sr = result.safety_route
    if sr is not None and sr.matched and sr.action == "block":
        return sr.route_name or "safety_route"
    return None


def _policy_hash(policy: GuardExPolicy) -> str:
    """Deterministic hash of policy for the audit header."""
    ts = policy.topic_scope
    data = {
        "cats": policy.blocked_categories,
        "pii": policy.pii_enabled,
        "pii_e": policy.pii_entities,
        "pii_a": policy.pii_action,
        "pii_t": policy.pii_threshold,
        "fo": policy.fail_open,
        "cm": policy.cascade_mode,
        "ts": ts.topics if ts else None,
        "ts_w": ts.scope_width if ts else None,
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:12]


class Guard:
    """Screen any text at any gate. Framework-agnostic.

    Parameters
    ----------
    api_key:
        GuardEx API key. Falls back to GUARDEX_API_KEY env var.
    base_url:
        GuardEx server URL. Falls back to GUARDEX_BASE_URL env var.
    policy:
        Optional GuardExPolicy for fine-grained configuration.
    fail_open:
        If True, treat server errors as SAFE (log warning).
    on_block:
        Optional callback invoked when content is blocked.
    on_screen:
        Optional callback invoked on every screening result.
    injection_check:
        When True (default), run client-side injection detection before the
        API call.  Adds no latency for clean content.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        policy: GuardExPolicy | None = None,
        fail_open: bool = False,
        on_block: Callable[[ScreenResult], None] | None = None,
        on_screen: Callable[[ScreenResult], None] | None = None,
        injection_check: bool = True,
        ollama_url: str | None = None,
    ) -> None:
        self._policy = policy or GuardExPolicy()
        effective_key = api_key or self._policy.api_key
        effective_url = base_url or self._policy.base_url
        effective_fail_open = fail_open or self._policy.fail_open

        # Local in-process mode when no API key or server URL is configured
        # via constructor args, the policy, or GUARDEX_API_KEY/GUARDEX_BASE_URL
        # env vars (policy defaults read the env vars).
        if not effective_key and not effective_url:
            # Local in-process mode - no server, no account required.
            try:
                from guardex._engine.runner import LocalRunner
                from guardex._engine.settings import local_settings
            except ImportError as e:
                raise ImportError(
                    "GuardEx zero-config local mode requires the [local] extras.\n"
                    "  pip install 'guardex-ai[local]'\n"
                    "Or pass a server URL: Guard(base_url='http://your-server:8001')\n"
                    "Or pass an API key:  Guard(api_key='gx_...')"
                ) from e
            if ollama_url:
                local_settings.ollama_url = ollama_url
            # Probe Ollama once at boot - if unreachable, disable the cascade
            # so the ONNX classifier decides alone. A speed-mode cascade would
            # still escalate middle-band scores to the dead Ollama and fail
            # closed on benign text. Suppressed when GUARDEX_CASCADE_MODE is
            # set explicitly so users keep control of their config.
            if (local_settings.cascade_mode == "safety"
                and "GUARDEX_CASCADE_MODE" not in os.environ
                and not _probe_ollama(local_settings.ollama_url,
                                      local_settings.ollama_model)):
                logger.warning(
                    "Ollama at %s is unreachable or does not have model %s - "
                    "using the ONNX classifier only. For full LlamaGuard "
                    "classification, run: `ollama pull %s` (and `ollama serve` "
                    "if not running), then set GUARDEX_OLLAMA_URL or pass "
                    "ollama_url= to Guard().",
                    local_settings.ollama_url, local_settings.ollama_model,
                    local_settings.ollama_model,
                )
                local_settings.cascade_enabled = False
                local_settings.cascade_mode = "speed"
                if self._policy.cascade_mode == "safety":
                    self._policy.cascade_mode = "speed"
            if self._policy.cascade_mode == "speed":
                from guardex.policy import _DEFAULT_BLOCKED
                global _WARNED_BLOCKED_CATEGORIES_INERT
                if (not _WARNED_BLOCKED_CATEGORIES_INERT
                        and set(self._policy.blocked_categories) != set(_DEFAULT_BLOCKED)):
                    _WARNED_BLOCKED_CATEGORIES_INERT = True
                    logger.warning(
                        "blocked_categories is customized but the local binary classifier "
                        "only distinguishes safe/toxic - per-category filtering has no effect "
                        "in 'speed' mode. Run Ollama (LlamaGuard) or use a multilabel model."
                    )
            self._client: Any = LocalRunner(fail_open=effective_fail_open)
            # Wire custom encoder from policy into scope engine
            ts = self._policy.topic_scope
            if ts and ts.encoder_type:
                self._configure_scope_encoder(ts.encoder_type, ts.encoder_config)
        else:
            self._client = GuardExClient(
                api_key=effective_key,
                base_url=effective_url,
                timeout=self._policy.timeout,
                fail_open=effective_fail_open,
            )
        self._async_client: AsyncGuardExClient | None = None

        self._resolver = CachedPolicyResolver(self._policy)
        self._on_block = on_block
        self._on_screen = on_screen
        self._injection_detector = InjectionDetector() if injection_check else None
        self._safety_route_engine: Any = None  # lazily built on first screen() call

    @property
    def policy(self) -> GuardExPolicy:
        """The active GuardExPolicy for this Guard instance."""
        return self._policy

    def _is_local_mode(self) -> bool:
        """True when this Guard talks to the in-process LocalRunner (not HTTP)."""
        return type(self._client).__name__ == "LocalRunner"

    @staticmethod
    def _configure_scope_encoder(encoder_type: str, encoder_config: dict | None) -> None:
        """Inject a custom encoder into the scope engine (local mode only)."""
        try:
            from guardex.encoders import create_encoder
            from guardex._engine.ml.model_manager import get_topic_scope_engine

            engine = get_topic_scope_engine()
            if engine is not None:
                encoder = create_encoder(encoder_type, **(encoder_config or {}))
                engine._encoder = encoder
                logger.info("Scope engine reconfigured with encoder: %s", encoder.name)
        except Exception as e:
            logger.warning("Failed to configure custom scope encoder: %s", e)

    def _get_safety_route_engine(self):
        """Build (lazily, once) the SafetyRouteEngine for ``policy.safety_routes``.

        Reuses the encoder from the topic-scope engine when present so we
        do not download or load a second sentence-transformer model.
        """
        if not self._policy.safety_routes:
            return None
        if self._safety_route_engine is not None:
            return self._safety_route_engine
        try:
            from guardex.safety_route import SafetyRouteEngine
            from guardex._engine.ml.model_manager import get_topic_scope_engine

            scope_engine = get_topic_scope_engine()
            shared_encoder = getattr(scope_engine, "_encoder", None) if scope_engine else None
            engine = SafetyRouteEngine(encoder=shared_encoder)
            engine.build(list(self._policy.safety_routes))
            self._safety_route_engine = engine
            return engine
        except Exception as e:
            logger.warning("Failed to build SafetyRouteEngine - routes disabled: %s", e)
            return None

    def _check_safety_routes(self, text: str):
        """Run ``policy.safety_routes`` against ``text`` and return SafetyRouteOutcome."""
        from ._types import SafetyRouteOutcome

        engine = self._get_safety_route_engine()
        if engine is None:
            return None
        try:
            r = engine.check(text)
        except Exception as e:
            logger.warning("SafetyRouteEngine.check failed: %s", e)
            return None
        return SafetyRouteOutcome(
            matched=r.matched, route_name=r.route_name, action=r.action,
            similarity=r.similarity, description=r.description,
        )

    def _scan_injection(self, text: str) -> tuple[bool, str | None]:
        """Run the client-side injection detector. Returns ``(blocked, pattern)``."""
        if not self._injection_detector:
            return False, None
        injection = self._injection_detector.scan(text)
        if injection.detected and injection.severity in ("high", "medium"):
            return True, injection.matched_pattern
        return False, None

    def _resolve_policy(self, context: GuardExContext | None) -> GuardExPolicy:
        """Resolve effective policy for a context, or return base policy."""
        if context is None:
            return self._policy
        return self._resolver.resolve(context)

    def _build_audit_headers(
        self,
        policy: GuardExPolicy,
        context: GuardExContext | None,
    ) -> dict[str, str]:
        """Build audit headers forwarded to the server for the policy trail."""
        headers: dict[str, str] = {}
        headers["X-GuardEx-Policy-Hash"] = _policy_hash(policy)
        if context is not None:
            headers["X-GuardEx-Context"] = context.to_header()
        return headers

    def screen(
        self,
        text: str,
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> ScreenResult:
        """Screen text at the specified gate.

        Returns a ScreenResult with .safe, .blocked, .classify, .pii, .text.
        Does NOT raise - check result.blocked to decide what to do.

        Parameters
        ----------
        text:
            The text to screen.
        gate:
            One of the 8 gates (input, output, tool_input, etc.)
        context:
            Optional :class:`~guardex.context.GuardExContext` for
            context-aware policy resolution.
        """
        # Client-side injection check - fires before the API call
        if self._injection_detector and gate in _INPUT_GATES:
            injection = self._injection_detector.scan(text)
            if injection.detected and injection.severity in ("high", "medium"):
                logger.warning(
                    "GuardEx injection detected at gate=%s: pattern=%s severity=%s",
                    gate, injection.matched_pattern, injection.severity,
                )
                injection_trace = (
                    GateTrace(
                        gate="injection",
                        ran=True,
                        blocked=True,
                        note=injection.matched_pattern,
                    ),
                )
                result = ScreenResult(
                    gate=gate,
                    action="block",
                    classify=ClassifyResult(
                        safe=False,
                        category="injection",
                        description=f"Prompt injection detected: {injection.matched_pattern}",
                    ),
                    pii=PIIResult(has_pii=False),
                    text=text,
                    gates_run=("injection",),
                    diagnostics=injection_trace,
                )
                self._fire_callbacks(result)
                return result

        start = time.monotonic()
        policy = self._resolve_policy(context)

        scope_kwargs: dict[str, Any] = {}
        ts = policy.topic_scope
        if ts and ts.topics:
            scope_kwargs["scope_topics"] = ts.topics
            if ts.utterances:
                scope_kwargs["scope_utterances"] = ts.utterances
            if ts.examples:
                scope_kwargs["scope_examples"] = ts.examples
            scope_kwargs["scope_width"] = ts.scope_width
            if ts.threshold is not None:
                scope_kwargs["scope_threshold"] = ts.threshold
            if ts.alpha > 0.0:
                scope_kwargs["scope_alpha"] = ts.alpha

        # PII customization is local-only; the server doesn't accept caller-supplied
        # regex patterns or word lists for security reasons.
        local_pii_kwargs: dict[str, Any] = {}
        if self._is_local_mode():
            if policy.pii_deny_list:
                local_pii_kwargs["pii_deny_list"] = policy.pii_deny_list
            if policy.pii_allow_list:
                local_pii_kwargs["pii_allow_list"] = policy.pii_allow_list
            if policy.pii_custom_regex:
                local_pii_kwargs["pii_custom_regex"] = policy.pii_custom_regex
            if policy.pii_custom_context_keywords:
                local_pii_kwargs["pii_custom_context_keywords"] = policy.pii_custom_context_keywords

        audit_headers = self._build_audit_headers(policy, context)

        with screening_span(gate) as span:
            raw, request_id = self._client.screen(
                text=text,
                stage=gate_to_stage(gate),
                pii_action=policy.pii_action if policy.pii_enabled else "none",
                categories=policy.blocked_categories,
                pii_entities=policy.pii_entities if policy.pii_enabled else None,
                pii_threshold=policy.pii_threshold,
                cascade_mode=policy.cascade_mode,
                audit_log=policy.audit_logging,
                extra_headers=audit_headers,
                **scope_kwargs,
                **local_pii_kwargs,
            )
            elapsed = (time.monotonic() - start) * 1000

            result = _parse_screen_result(
                raw, gate, text, request_id,
                min_confidence=policy.classify_min_confidence,
                pii_action=policy.pii_action if policy.pii_enabled else "none",
            )
            route_outcome = self._check_safety_routes(text)
            action = result.action
            extra_traces: tuple[GateTrace, ...] = ()
            extra_gates: tuple[str, ...] = ()
            if route_outcome:
                extra_traces = (
                    GateTrace(
                        gate="safety_route",
                        ran=True,
                        blocked=(route_outcome.matched and route_outcome.action == "block"),
                        note=route_outcome.route_name,
                    ),
                )
                extra_gates = ("safety_route",)
            if route_outcome and route_outcome.matched and route_outcome.action == "block":
                action = "block"
            result = ScreenResult(
                gate=result.gate,
                action=action,
                classify=result.classify,
                pii=result.pii,
                text=result.text,
                scope=result.scope,
                safety_route=route_outcome,
                latency_ms=elapsed,
                request_id=result.request_id,
                gates_run=result.gates_run + extra_gates,
                diagnostics=result.diagnostics + extra_traces,
                degraded=result.degraded,
            )

            record_result(span, result)

        if policy.audit_logging:
            emit_audit_log(
                gate=gate,
                action=result.action,
                safe=result.safe,
                category=result.classify.category,
                request_id=result.request_id,
                latency_ms=result.latency_ms,
                pii_detected=result.pii.has_pii,
                pii_count=len(result.pii.entities),
                detailed=policy.detailed_logging,
                text_preview=text if policy.detailed_logging else None,
            )

        if policy.detailed_logging:
            logger.debug(
                "GuardEx screen: gate=%s action=%s safe=%s category=%s "
                "pii=%d latency=%.1fms request_id=%s",
                gate, result.action, result.safe, result.classify.category,
                len(result.pii.entities), result.latency_ms, result.request_id,
            )

        self._fire_callbacks(result)

        return result

    def screen_or_raise(
        self,
        text: str,
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> str:
        """Screen text. Returns (possibly masked) text, or raises on unsafe.

        ``block_on_unsafe_input`` / ``block_on_unsafe_output`` gate the
        safety-classifier verdict only. Prompt injection, topic scope,
        safety routes, and ``pii_action="block"`` always raise, so
        observe-only mode never silently disables them.

        Raises
        ------
        GuardExViolation
            If content is blocked and the block source is enforced for
            this gate (see :func:`_enforce_block`).
        """
        result = self.screen(text, gate, context=context)
        if result.blocked and _enforce_block(result, gate, self._resolve_policy(context)):
            raise GuardExViolation(
                stage=gate,
                category=_block_category(result),
                description=result.classify.description,
            )
        return result.text

    def classify(
        self,
        text: str,
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> ClassifyResult:
        """Classify text for safety only (no PII scanning)."""
        policy = self._resolve_policy(context)
        # The HTTP /v1/classify endpoint takes no cascade_mode; only the
        # in-process runner honors it.
        classify_kwargs: dict[str, Any] = (
            {"cascade_mode": policy.cascade_mode} if self._is_local_mode() else {}
        )
        raw = self._client.classify(
            text=text,
            stage=gate_to_stage(gate),
            categories=policy.blocked_categories,
            **classify_kwargs,
        )
        if raw.get("_fail_open"):
            return ClassifyResult(safe=True)
        return ClassifyResult(
            safe=raw.get("safe", True),
            category=raw.get("category"),
            categories=raw.get("categories", []),
            confidence=raw.get("confidence", 1.0),
            description=raw.get("description"),
        )

    def pii_scan(
        self,
        text: str,
        context: GuardExContext | None = None,
    ) -> PIIResult:
        """Scan text for PII only (no safety classification)."""
        policy = self._resolve_policy(context)
        raw = self._client.pii_scan(
            text=text,
            entities=policy.pii_entities,
            threshold=policy.pii_threshold,
        )
        if raw.get("_fail_open"):
            return PIIResult(has_pii=False)
        entities = [
            PIIEntity(
                text=e.get("text", ""),
                label=e.get("label", ""),
                score=e.get("score", 0.0),
                start=e.get("start", 0),
                end=e.get("end", 0),
            )
            for e in raw.get("entities", [])
        ]
        return PIIResult(has_pii=raw.get("has_pii", False), entities=entities)

    def pii_mask(
        self,
        text: str,
        context: GuardExContext | None = None,
    ) -> str:
        """Mask PII in text. Returns masked text."""
        policy = self._resolve_policy(context)
        raw = self._client.pii_mask(
            text=text,
            entities=policy.pii_entities,
            threshold=policy.pii_threshold,
        )
        return raw.get("masked_text", text)

    def screen_batch(
        self,
        texts: List[str],
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> List[ScreenResult]:
        """Screen a batch of texts in a single round-trip.

        Parameters
        ----------
        texts:
            List of texts to screen.
        gate:
            Gate applied to all texts in the batch.
        context:
            Optional context for policy resolution.

        Returns
        -------
        list[ScreenResult]
            One result per input text, in the same order.
        """
        if not texts:
            return []

        policy = self._resolve_policy(context)
        audit_headers = self._build_audit_headers(policy, context)

        raw_results = self._client.screen_batch(
            texts=texts,
            stage=gate_to_stage(gate),
            pii_action=policy.pii_action if policy.pii_enabled else "none",
            categories=policy.blocked_categories,
            pii_entities=policy.pii_entities if policy.pii_enabled else None,
            pii_threshold=policy.pii_threshold,
            cascade_mode=policy.cascade_mode,
            extra_headers=audit_headers,
        )

        results = []
        for i, raw in enumerate(raw_results):
            original = texts[i] if i < len(texts) else ""
            result = _parse_screen_result(
                raw, gate, original,
                min_confidence=policy.classify_min_confidence,
                pii_action=policy.pii_action if policy.pii_enabled else "none",
            )
            route_outcome = self._check_safety_routes(original)
            if route_outcome:
                action = "block" if (route_outcome.matched and route_outcome.action == "block") else result.action
                route_trace = GateTrace(
                    gate="safety_route",
                    ran=True,
                    blocked=(route_outcome.matched and route_outcome.action == "block"),
                    note=route_outcome.route_name,
                )
                result = ScreenResult(
                    gate=result.gate, action=action, classify=result.classify,
                    pii=result.pii, text=result.text, scope=result.scope,
                    safety_route=route_outcome, latency_ms=result.latency_ms,
                    request_id=result.request_id,
                    gates_run=result.gates_run + ("safety_route",),
                    diagnostics=result.diagnostics + (route_trace,),
                    degraded=result.degraded,
                )
            results.append(result)
            self._fire_callbacks(result)

        return results

    def check_grounding(
        self,
        response_text: str,
        sources: list[str],
        mode: str | None = None,
        threshold: float | None = None,
    ) -> "GroundingResult":
        """Check if an LLM response is grounded in source documents.

        Parameters
        ----------
        response_text:
            The LLM output to verify.
        sources:
            Source document chunks that the response should be grounded in.
        mode:
            'speed' (embedding only) or 'accuracy' (NLI hybrid).
            Falls back to ``policy.grounding_mode`` if not provided.
        threshold:
            Per-sentence grounded score threshold override.
            Falls back to ``policy.grounding_threshold`` if not provided.

        Returns
        -------
        GroundingResult
            With .grounded, .hallucinated, .faithfulness_score, .details, etc.
        """
        effective_mode = mode if mode is not None else self._policy.grounding_mode
        effective_threshold = threshold if threshold is not None else self._policy.grounding_threshold
        audit_headers = {"X-GuardEx-Policy-Hash": _policy_hash(self._policy)}

        raw, request_id = self._client.check_grounding(
            response_text=response_text,
            sources=sources,
            mode=effective_mode,
            threshold=effective_threshold,
            extra_headers=audit_headers,
        )

        return _parse_grounding_result(raw, request_id)

    async def acheck_grounding(
        self,
        response_text: str,
        sources: list[str],
        mode: str | None = None,
        threshold: float | None = None,
    ) -> "GroundingResult":
        """Async version of check_grounding().

        Local mode dispatches to the sync ``check_grounding`` via
        ``asyncio.to_thread`` so async frameworks work without HTTP.
        """
        if self._is_local_mode():
            return await asyncio.to_thread(
                self.check_grounding, response_text, sources, mode, threshold,
            )
        effective_mode = mode if mode is not None else self._policy.grounding_mode
        effective_threshold = threshold if threshold is not None else self._policy.grounding_threshold
        client = self._get_async_client()
        audit_headers = {"X-GuardEx-Policy-Hash": _policy_hash(self._policy)}

        raw, request_id = await client.check_grounding(
            response_text=response_text,
            sources=sources,
            mode=effective_mode,
            threshold=effective_threshold,
            extra_headers=audit_headers,
        )

        return _parse_grounding_result(raw, request_id)

    def screen_grounded(
        self,
        response_text: str,
        sources: list[str],
        gate: Gate = "output",
        context: GuardExContext | None = None,
        grounding_mode: str | None = None,
        grounding_threshold: float | None = None,
    ) -> tuple[ScreenResult, "GroundingResult"]:
        """Screen output for safety AND verify grounding in one call.

        If screen blocks, grounding is skipped.
        """
        from ._types import GroundingResult

        screen_result = self.screen(response_text, gate=gate, context=context)

        if screen_result.blocked:
            placeholder = GroundingResult(grounded=True, mode="skipped")
            return screen_result, placeholder

        grounding_result = self.check_grounding(
            response_text=screen_result.text,
            sources=sources,
            mode=grounding_mode,
            threshold=grounding_threshold,
        )

        return screen_result, grounding_result

    async def ascreen_grounded(
        self,
        response_text: str,
        sources: list[str],
        gate: Gate = "output",
        context: GuardExContext | None = None,
        grounding_mode: str | None = None,
        grounding_threshold: float | None = None,
    ) -> tuple[ScreenResult, "GroundingResult"]:
        """Async version of screen_grounded().

        Local mode dispatches to the sync ``screen_grounded`` via
        ``asyncio.to_thread``.
        """
        if self._is_local_mode():
            return await asyncio.to_thread(
                self.screen_grounded,
                response_text, sources, gate, context,
                grounding_mode, grounding_threshold,
            )

        from ._types import GroundingResult

        screen_result = await self.ascreen(response_text, gate=gate, context=context)

        if screen_result.blocked:
            placeholder = GroundingResult(grounded=True, mode="skipped")
            return screen_result, placeholder

        grounding_result = await self.acheck_grounding(
            response_text=screen_result.text,
            sources=sources,
            mode=grounding_mode,
            threshold=grounding_threshold,
        )

        return screen_result, grounding_result

    def wrap(
        self,
        fn: Callable[..., str],
        gate: Gate = "tool_input",
        screen_output: bool = True,
    ) -> Callable[..., str]:
        """Wrap any callable: screen input, optionally screen output.

        All positional string arguments are screened, not just the first.

        Usage::

            safe_search = guard.wrap(search_web, gate="tool_input")
            result = safe_search("user query")  # screened both ways
        """
        out_gate = output_gate_for(gate) if screen_output else None

        def wrapped(*args: Any, **kwargs: Any) -> str:
            # Screen all string args, not just the first
            new_args = list(args)
            for i, arg in enumerate(new_args):
                if isinstance(arg, str):
                    new_args[i] = self.screen_or_raise(arg, gate)

            result = fn(*new_args, **kwargs)

            if out_gate and isinstance(result, str):
                return self.screen_or_raise(result, out_gate)
            return result

        wrapped.__name__ = getattr(fn, "__name__", "wrapped")
        wrapped.__doc__ = f"GuardEx-wrapped: {getattr(fn, '__doc__', '')}"
        return wrapped

    def stream(
        self,
        chunks: Iterator[str],
        gate: Gate = "output",
        flush_every: int = 256,
        context: GuardExContext | None = None,
        vault: Any | None = None,
        restore_mode: str = "off",
        mask_output_pii: bool = False,
    ) -> Iterator[str]:
        """Screen a stream of text chunks.

        Buffers chunks and screens at content boundaries or flush_every chars.
        Yields screened text. Raises GuardExViolation on unsafe content.

        Works with ANY streaming source - OpenAI, Anthropic, LangChain,
        raw SSE, websockets. Anything that yields strings.

        On output gates PII is not masked by default (LLM-generated names
        are not real personal data). Pass ``mask_output_pii=True`` to mask
        PII on output gates too.

        Pass ``vault=`` with ``restore_mode="buffered"`` (correctness-first)
        or ``"stream-safe"`` (preserves streaming UX) to restore PII vault
        tokens emitted by the upstream LLM.

        Usage::

            for chunk in guard.stream(openai_chunks(), gate="output"):
                print(chunk, end="", flush=True)
        """
        from .stream import StreamGuard
        policy = self._resolve_policy(context)
        sg = StreamGuard(
            self._client, policy, gate, flush_every,
            vault=vault, restore_mode=restore_mode,  # type: ignore[arg-type]
            mask_output_pii=mask_output_pii,
            injection_check=self._scan_injection if self._injection_detector else None,
            safety_route_check=self._check_safety_routes if policy.safety_routes else None,
        )
        yield from sg.run(chunks)

    async def ascreen(
        self,
        text: str,
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> ScreenResult:
        """Async version of screen().

        In local (in-process) mode the call is dispatched to the sync
        ``screen`` via ``asyncio.to_thread`` so async frameworks (FastAPI,
        Starlette, aiohttp) work without any HTTP transport.
        """
        if self._is_local_mode():
            return await asyncio.to_thread(self.screen, text, gate, context)

        # Client-side injection check - fires before the API call
        if self._injection_detector and gate in _INPUT_GATES:
            injection = self._injection_detector.scan(text)
            if injection.detected and injection.severity in ("high", "medium"):
                logger.warning(
                    "GuardEx injection detected at gate=%s (async): pattern=%s severity=%s",
                    gate, injection.matched_pattern, injection.severity,
                )
                injection_trace = (
                    GateTrace(
                        gate="injection",
                        ran=True,
                        blocked=True,
                        note=injection.matched_pattern,
                    ),
                )
                result = ScreenResult(
                    gate=gate,
                    action="block",
                    classify=ClassifyResult(
                        safe=False,
                        category="injection",
                        description=f"Prompt injection detected: {injection.matched_pattern}",
                    ),
                    pii=PIIResult(has_pii=False),
                    text=text,
                    gates_run=("injection",),
                    diagnostics=injection_trace,
                )
                self._fire_callbacks(result)
                return result

        start = time.monotonic()
        client = self._get_async_client()
        policy = self._resolve_policy(context)

        scope_kwargs: dict[str, Any] = {}
        ts = policy.topic_scope
        if ts and ts.topics:
            scope_kwargs["scope_topics"] = ts.topics
            if ts.utterances:
                scope_kwargs["scope_utterances"] = ts.utterances
            if ts.examples:
                scope_kwargs["scope_examples"] = ts.examples
            scope_kwargs["scope_width"] = ts.scope_width
            if ts.threshold is not None:
                scope_kwargs["scope_threshold"] = ts.threshold
            if ts.alpha > 0.0:
                scope_kwargs["scope_alpha"] = ts.alpha

        audit_headers = self._build_audit_headers(policy, context)

        with screening_span(gate) as span:
            raw, request_id = await client.screen(
                text=text,
                stage=gate_to_stage(gate),
                pii_action=policy.pii_action if policy.pii_enabled else "none",
                categories=policy.blocked_categories,
                pii_entities=policy.pii_entities if policy.pii_enabled else None,
                pii_threshold=policy.pii_threshold,
                cascade_mode=policy.cascade_mode,
                audit_log=policy.audit_logging,
                extra_headers=audit_headers,
                **scope_kwargs,
            )
            elapsed = (time.monotonic() - start) * 1000

            result = _parse_screen_result(
                raw, gate, text, request_id,
                min_confidence=policy.classify_min_confidence,
                pii_action=policy.pii_action if policy.pii_enabled else "none",
            )
            route_outcome = self._check_safety_routes(text)
            action = result.action
            extra_traces: tuple[GateTrace, ...] = ()
            extra_gates: tuple[str, ...] = ()
            if route_outcome:
                extra_traces = (
                    GateTrace(
                        gate="safety_route",
                        ran=True,
                        blocked=(route_outcome.matched and route_outcome.action == "block"),
                        note=route_outcome.route_name,
                    ),
                )
                extra_gates = ("safety_route",)
            if route_outcome and route_outcome.matched and route_outcome.action == "block":
                action = "block"
            result = ScreenResult(
                gate=result.gate,
                action=action,
                classify=result.classify,
                pii=result.pii,
                text=result.text,
                scope=result.scope,
                safety_route=route_outcome,
                latency_ms=elapsed,
                request_id=result.request_id,
                gates_run=result.gates_run + extra_gates,
                diagnostics=result.diagnostics + extra_traces,
                degraded=result.degraded,
            )
            record_result(span, result)

        if policy.audit_logging:
            emit_audit_log(
                gate=gate,
                action=result.action,
                safe=result.safe,
                category=result.classify.category,
                request_id=result.request_id,
                latency_ms=result.latency_ms,
                pii_detected=result.pii.has_pii,
                pii_count=len(result.pii.entities),
                detailed=policy.detailed_logging,
                text_preview=text if policy.detailed_logging else None,
            )

        self._fire_callbacks(result)
        return result

    async def ascreen_or_raise(
        self,
        text: str,
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> str:
        """Async version of screen_or_raise().

        Local mode bridges to the sync ``screen_or_raise`` via ``asyncio.to_thread``.
        """
        if self._is_local_mode():
            return await asyncio.to_thread(self.screen_or_raise, text, gate, context)
        result = await self.ascreen(text, gate, context=context)
        if result.blocked and _enforce_block(result, gate, self._resolve_policy(context)):
            raise GuardExViolation(
                stage=gate,
                category=_block_category(result),
                description=result.classify.description,
            )
        return result.text

    async def ascreen_batch(
        self,
        texts: List[str],
        gate: Gate = "input",
        context: GuardExContext | None = None,
    ) -> List[ScreenResult]:
        """Async version of screen_batch().

        Local mode bridges to the sync ``screen_batch`` via ``asyncio.to_thread``.
        """
        if not texts:
            return []

        if self._is_local_mode():
            return await asyncio.to_thread(self.screen_batch, texts, gate, context)

        policy = self._resolve_policy(context)
        client = self._get_async_client()
        audit_headers = self._build_audit_headers(policy, context)

        raw_results = await client.screen_batch(
            texts=texts,
            stage=gate_to_stage(gate),
            pii_action=policy.pii_action if policy.pii_enabled else "none",
            categories=policy.blocked_categories,
            pii_entities=policy.pii_entities if policy.pii_enabled else None,
            pii_threshold=policy.pii_threshold,
            cascade_mode=policy.cascade_mode,
            extra_headers=audit_headers,
        )

        results = []
        for i, raw in enumerate(raw_results):
            original = texts[i] if i < len(texts) else ""
            result = _parse_screen_result(
                raw, gate, original,
                min_confidence=policy.classify_min_confidence,
                pii_action=policy.pii_action if policy.pii_enabled else "none",
            )
            route_outcome = self._check_safety_routes(original)
            if route_outcome:
                action = "block" if (route_outcome.matched and route_outcome.action == "block") else result.action
                route_trace = GateTrace(
                    gate="safety_route",
                    ran=True,
                    blocked=(route_outcome.matched and route_outcome.action == "block"),
                    note=route_outcome.route_name,
                )
                result = ScreenResult(
                    gate=result.gate, action=action, classify=result.classify,
                    pii=result.pii, text=result.text, scope=result.scope,
                    safety_route=route_outcome, latency_ms=result.latency_ms,
                    request_id=result.request_id,
                    gates_run=result.gates_run + ("safety_route",),
                    diagnostics=result.diagnostics + (route_trace,),
                    degraded=result.degraded,
                )
            results.append(result)
            self._fire_callbacks(result)
        return results

    async def astream(
        self,
        chunks: AsyncIterator[str],
        gate: Gate = "output",
        flush_every: int = 256,
        context: GuardExContext | None = None,
        vault: Any | None = None,
        restore_mode: str = "off",
        mask_output_pii: bool = False,
    ) -> AsyncIterator[str]:
        """Async version of stream(). Screens async chunk iterators.

        In local mode the async stream is consumed and re-screened through
        the sync pipeline via ``asyncio.to_thread`` so callers don't need
        an HTTP transport.  The check-safety-then-yield contract matches the
        remote-mode path: a violation raises ``GuardExViolation`` immediately.

        On output gates PII is not masked by default; pass
        ``mask_output_pii=True`` to mask PII on output gates too.

        Pass ``vault=`` with ``restore_mode="buffered"`` or ``"stream-safe"``
        to restore PII vault tokens in the LLM output stream so callers see
        original values instead of ``{{pii:...}}`` placeholders.
        """
        if self._is_local_mode():
            from .exceptions import GuardExViolation
            from .stream import _VAULT_TOKEN_PREFIX, _VAULT_TOKEN_END
            from ._stream_base import run_local_gates, screen_kwargs_for_buffer

            policy = self._resolve_policy(context)
            buf: list[str] = []
            buf_chars = 0
            effective_restore = restore_mode if vault is not None else "off"
            restore_pending = ""
            stream_screen_kwargs = screen_kwargs_for_buffer(
                policy,
                gate,
                audit_log=policy.audit_logging,
                mask_output_pii=mask_output_pii,
            )
            pii_action = stream_screen_kwargs["pii_action"]

            local_pii_kwargs: dict[str, Any] = {}
            if policy.pii_deny_list:
                local_pii_kwargs["pii_deny_list"] = policy.pii_deny_list
            if policy.pii_allow_list:
                local_pii_kwargs["pii_allow_list"] = policy.pii_allow_list
            if policy.pii_custom_regex:
                local_pii_kwargs["pii_custom_regex"] = policy.pii_custom_regex
            if policy.pii_custom_context_keywords:
                local_pii_kwargs["pii_custom_context_keywords"] = policy.pii_custom_context_keywords

            def _restore(emit: str) -> tuple[str, str]:
                """Apply vault restore_mode to ``emit``; return (safe_to_emit, new_pending)."""
                nonlocal restore_pending
                if effective_restore == "off":
                    return emit, restore_pending
                if effective_restore == "buffered":
                    return "", restore_pending + emit
                # stream-safe
                combined = restore_pending + emit
                last_open = combined.rfind(_VAULT_TOKEN_PREFIX)
                last_close = combined.rfind(_VAULT_TOKEN_END)
                if last_open != -1 and last_open > last_close:
                    safe, new_pending = combined[:last_open], combined[last_open:]
                else:
                    safe, new_pending = combined, ""
                return vault.restore(safe) if safe else "", new_pending

            async def _flush_local() -> AsyncIterator[str]:
                nonlocal buf, buf_chars, restore_pending
                if not buf:
                    return
                full = "".join(buf)
                # Drain buffer first so re-entry sees a clean slate
                buf = []
                buf_chars = 0
                run_local_gates(
                    full,
                    gate,
                    self._scan_injection if self._injection_detector else None,
                    self._check_safety_routes if policy.safety_routes else None,
                )
                raw, request_id = await asyncio.to_thread(
                    self._client.screen,
                    text=full,
                    stage=gate_to_stage(gate),
                    **stream_screen_kwargs,
                    **local_pii_kwargs,
                )
                r = _parse_screen_result(
                    raw,
                    gate,
                    full,
                    request_id,
                    min_confidence=policy.classify_min_confidence,
                    pii_action=pii_action,
                )
                if r.blocked:
                    raise GuardExViolation(
                        stage=gate,
                        category=_block_category(r),
                        description=r.classify.description,
                    )
                text_to_emit = r.text if (pii_action == "mask" and r.text) else full
                emit, restore_pending = _restore(text_to_emit)
                if emit:
                    yield emit

            async for chunk in chunks:
                buf.append(chunk)
                buf_chars += len(chunk)
                if buf_chars >= flush_every:
                    async for piece in _flush_local():
                        yield piece
            async for piece in _flush_local():
                yield piece

            # Drain any vault-pending tail (buffered + stream-safe modes).
            if restore_pending and vault is not None:
                yield vault.restore(restore_pending)
            elif restore_pending:
                yield restore_pending
            return

        from .stream import AsyncStreamGuard
        client = self._get_async_client()
        policy = self._resolve_policy(context)
        sg = AsyncStreamGuard(
            client, policy, gate, flush_every,
            vault=vault, restore_mode=restore_mode,  # type: ignore[arg-type]
            mask_output_pii=mask_output_pii,
            injection_check=self._scan_injection if self._injection_detector else None,
            safety_route_check=self._check_safety_routes if policy.safety_routes else None,
        )
        async for chunk in sg.run(chunks):
            yield chunk

    def warmup(self) -> None:
        """Eagerly load all ML providers and models in local mode.

        On a cold cache this triggers GLiNER (~150 MB), sentence-transformers
        (~90 MB), the ONNX classifier and (if enabled) the NLI grounding model
        (~700 MB) to download.  Call from your app's startup hook so the
        first ``screen()`` is fast.  No-op in server (HTTP) mode.

        Raises
        ------
        ImportError
            If the ``[local]`` extras are not installed.
        """
        if not self._is_local_mode():
            return
        from guardex._engine.runner import _ensure_providers
        _ensure_providers()

    async def awarmup(self) -> None:
        """Async version of :meth:`warmup`. Runs the loader in a worker thread."""
        if not self._is_local_mode():
            return
        await asyncio.to_thread(self.warmup)

    @staticmethod
    def cache_info() -> dict[str, Any]:
        """Return paths and sizes of the on-disk caches GuardEx writes to.

        Two locations are reported because Hugging Face's ``hf_hub_download``
        cache and GuardEx's own cache can be mounted independently in
        containers - missing either one will trigger re-downloads on every
        restart.
        """
        try:
            from guardex._engine.settings import local_settings
            guardex_dir = Path(local_settings.cache_dir)
        except Exception:
            guardex_dir = Path.home() / ".cache" / "guardex"

        hf_home = os.environ.get("HF_HOME")
        if hf_home:
            hf_dir = Path(hf_home) / "hub"
        else:
            hf_dir = Path.home() / ".cache" / "huggingface" / "hub"

        def _bytes(p: Path) -> int:
            if not p.exists():
                return 0
            total = 0
            for root, _, files in os.walk(p):
                for f in files:
                    try:
                        total += (Path(root) / f).stat().st_size
                    except OSError:
                        pass
            return total

        info = {
            "guardex_cache": {
                "path": str(guardex_dir),
                "exists": guardex_dir.exists(),
                "size_bytes": _bytes(guardex_dir),
            },
            "huggingface_hub": {
                "path": str(hf_dir),
                "exists": hf_dir.exists(),
                "size_bytes": _bytes(hf_dir),
            },
        }
        info["total_bytes"] = (
            info["guardex_cache"]["size_bytes"] + info["huggingface_hub"]["size_bytes"]
        )
        return info

    def close(self) -> None:
        """Close underlying HTTP clients."""
        self._client.close()

    def __enter__(self) -> Guard:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    async def __aenter__(self) -> Guard:
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._async_client:
            await self._async_client.aclose()
        self.close()

    def _get_async_client(self) -> AsyncGuardExClient:
        if not self._async_client:
            if not hasattr(self._client, "api_key"):
                # Local-mode async paths bridge to sync via asyncio.to_thread,
                # so this branch should be unreachable for documented usage.
                # Kept for forward-compat with custom transports.
                raise RuntimeError(
                    "Async HTTP transport unavailable: this Guard is in local "
                    "(in-process) mode. Use ascreen()/ascreen_batch() - they "
                    "now bridge to sync automatically - or pass api_key=/base_url=."
                )
            self._async_client = AsyncGuardExClient(
                api_key=self._client.api_key,
                base_url=self._client.base_url,
                timeout=self._policy.timeout,
                fail_open=self._client.fail_open,
            )
        return self._async_client

    def _fire_callbacks(self, result: ScreenResult) -> None:
        """Invoke on_screen and on_block callbacks if registered."""
        if self._on_screen:
            try:
                self._on_screen(result)
            except Exception:
                logger.warning("on_screen callback error", exc_info=True)

        if result.blocked and self._on_block:
            try:
                self._on_block(result)
            except Exception:
                logger.warning("on_block callback error", exc_info=True)

    def __repr__(self) -> str:
        base_url = getattr(self._client, "base_url", "local")
        fail_open = getattr(self._client, "fail_open", False)
        return f"Guard(base_url={base_url!r}, fail_open={fail_open})"
