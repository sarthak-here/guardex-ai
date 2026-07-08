# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Cascade safety classifier.

Pipeline: keyword gate (block on match) → text normalization (NFKC,
leet expansion, homoglyphs) → fast ONNX classifier (block above
``unsafe_threshold``) → LlamaGuard escalation for full S1-S14
classification (always in "safety" mode; only the uncertain band in
"speed" mode). Escalation failures honor ``fail_open``.

Metrics tracked via ``guardex._engine.ml.metrics``; decisions logged via
``guardex._engine.ml.safety_logger``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any

import numpy as np

from guardex._engine.ml.keyword_gate import check_keyword_gate
from guardex._engine.ml.metrics import CASCADE_PATH, KEYWORD_GATE, NORMALIZATION_CHANGES
from guardex._engine.ml.onnx_engine import _softmax
from guardex._engine.ml.text_normalizer import normalize_for_classification

logger = logging.getLogger(__name__)


class CascadeClassifierProvider:
    """Multi-layer cascade: keyword gate → normalization → ONNX → LlamaGuard.

    Parameters
    ----------
    fast_engine:
        OnnxSafetyEngine instance for the fast first pass.
    slow_provider:
        ClassifierProvider (LlamaGuard or any compatible model) for uncertain cases.
    safe_threshold:
        Below this toxic probability → SAFE (no escalation). Only used in SPEED mode.
    unsafe_threshold:
        Above this toxic probability → UNSAFE (no escalation). Used in both modes.
    mode:
        "safety" or "speed".
    normalize:
        Enable text normalization before ONNX classification.
    keyword_gate:
        Enable keyword-based safety gate (Layer 0).
    """

    name: str = "guardex-shield-cascade-v1"

    def __init__(
        self,
        fast_engine: Any,
        slow_provider: Any,
        safe_threshold: float = 0.15,
        unsafe_threshold: float = 0.85,
        mode: str = "safety",
        normalize: bool = True,
        keyword_gate: bool = True,
        fail_open: bool = False,
    ) -> None:
        self._fast = fast_engine
        self._slow = slow_provider
        self._safe_threshold = safe_threshold
        self._unsafe_threshold = unsafe_threshold
        self._mode = mode
        self._normalize = normalize
        self._keyword_gate = keyword_gate
        self._fail_open = fail_open

        # Metrics (protected by lock for concurrent requests)
        self._stats_lock = threading.Lock()
        self._fast_resolved = 0
        self._escalated = 0
        self._fast_blocked = 0
        self._fast_passed = 0
        self._keyword_blocked = 0
        self._total = 0

        # Escalation circuit breaker: after _BREAKER_THRESHOLD consecutive
        # failures, skip escalation for _BREAKER_COOLDOWN seconds instead of
        # paying a full timeout per call while Ollama is down or cold-loading.
        self._escalate_failures = 0
        self._escalate_retry_at = 0.0

    _BREAKER_THRESHOLD = 3
    _BREAKER_COOLDOWN = 60.0

    async def classify(
        self,
        text: str,
        stage: str = "input",
        categories: list[str] | None = None,
        cascade_mode: str | None = None,
    ) -> dict[str, Any]:
        """Cascade classification: keyword → normalize → ONNX → LlamaGuard.

        Parameters
        ----------
        cascade_mode : str | None
            Per-request override of self._mode ('safety' or 'speed').
            If None, uses the instance default from settings.

        Returns dict with keys: safe, category, categories, _cascade_path
        """
        with self._stats_lock:
            self._total += 1

        # Layer 0: Keyword safety gate (~0ms)
        if self._keyword_gate:
            kw_result = check_keyword_gate(text)
            if kw_result.matched:
                with self._stats_lock:
                    self._fast_resolved += 1
                    self._keyword_blocked += 1
                KEYWORD_GATE.inc(matched="true")
                CASCADE_PATH.inc(path="keyword_gate")
                return {
                    "safe": False,
                    "category": kw_result.category,
                    "categories": [kw_result.category],
                    "_cascade_path": "keyword_gate",
                    "_keyword_pattern": kw_result.pattern,
                    "_normalized": False,
                }
            KEYWORD_GATE.inc(matched="false")

        # Preprocessing: Text normalization (~1ms)
        classify_text = text
        text_changed = False
        if self._normalize:
            classify_text = normalize_for_classification(text)
            text_changed = classify_text != text
            NORMALIZATION_CHANGES.inc(changed="true" if text_changed else "false")
            if text_changed:
                logger.debug("Normalization changed input (len %d → %d)", len(text), len(classify_text))

        # Layer 1: Fast ONNX classifier (~20ms)
        try:
            fast_result, toxic_prob = await self._fast_classify(classify_text, stage)
        except Exception as e:
            logger.warning("Fast classifier failed: %s - escalating", e)
            CASCADE_PATH.inc(path="fast_error")
            return await self._escalate(
                classify_text, stage, categories, reason="fast_error",
            )

        # Layer 2: Decide based on confidence + mode

        # CLEARLY TOXIC - high confidence toxic (both modes)
        if toxic_prob > self._unsafe_threshold:
            with self._stats_lock:
                self._fast_resolved += 1
                self._fast_blocked += 1
            CASCADE_PATH.inc(path="fast_unsafe")
            return {
                "safe": False,
                "category": None,
                "categories": [],
                "_cascade_path": "fast_unsafe",
                "_toxic_prob": round(float(toxic_prob), 4),
                "_normalized": text_changed,
            }

        # Use per-request cascade_mode override if provided, else instance
        # default. Anything other than a valid mode falls back to "safety"
        # (the stricter path) - a typo must not silently weaken screening.
        effective_mode = cascade_mode or self._mode
        if effective_mode not in ("safety", "speed"):
            logger.warning(
                "Invalid cascade_mode %r; using 'safety'", effective_mode
            )
            effective_mode = "safety"

        # SAFETY MODE: everything non-toxic escalates to LlamaGuard
        if effective_mode == "safety":
            CASCADE_PATH.inc(path="escalated_safety_mode")
            return await self._escalate(
                classify_text, stage, categories,
                reason="safety_mode",
                toxic_prob=toxic_prob,
                normalized=text_changed,
                fast_result=fast_result,
            )

        # SPEED MODE: three-way decision
        if toxic_prob < self._safe_threshold:
            with self._stats_lock:
                self._fast_resolved += 1
                self._fast_passed += 1
            CASCADE_PATH.inc(path="fast_safe")
            return {
                "safe": True,
                "category": None,
                "categories": [],
                "_cascade_path": "fast_safe",
                "_toxic_prob": round(float(toxic_prob), 4),
                "_normalized": text_changed,
            }

        # UNCERTAIN - escalate. The escalation model sees the same
        # normalized text the fast model saw, so obfuscated input cannot
        # dodge the slow path by arriving denormalized.
        CASCADE_PATH.inc(path="escalated_uncertain")
        return await self._escalate(
            classify_text, stage, categories,
            reason="uncertain",
            toxic_prob=toxic_prob,
            normalized=text_changed,
            fast_result=fast_result,
        )

    async def _fast_classify(self, text: str, stage: str) -> tuple[dict, float]:
        """Run the fast ONNX classifier and extract toxic probability.

        Returns (result_dict, toxic_probability).
        """
        # Run in thread pool (ONNX is CPU-bound)
        encoded = await asyncio.to_thread(
            self._fast._tokenizer,
            f"[{stage.upper()}] {text}",
            max_length=self._fast._max_length,
            truncation=True,
            padding="max_length",
            return_tensors="np",
        )

        feed = {}
        for name in self._fast._input_names:
            if name == "input_ids":
                feed[name] = encoded["input_ids"].astype(np.int64)
            elif name == "attention_mask":
                feed[name] = encoded["attention_mask"].astype(np.int64)
            elif name == "token_type_ids" and "token_type_ids" in encoded:
                feed[name] = encoded["token_type_ids"].astype(np.int64)

        outputs = await asyncio.to_thread(
            self._fast._session.run, self._fast._output_names, feed,
        )
        logits = outputs[0][0]

        probs = _softmax(logits)

        # Index 1 = toxic probability (from label_map: {0: "neutral/safe", 1: "toxic/unsafe"})
        toxic_prob = probs[1] if len(probs) > 1 else probs[0]

        result = self._fast._parse_logits(logits)
        return result, toxic_prob

    async def _escalate(
        self,
        text: str,
        stage: str,
        categories: list[str] | None,
        reason: str = "uncertain",
        toxic_prob: float | None = None,
        normalized: bool = False,
        fast_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Escalate to LlamaGuard for full S1-S14 classification.

        On escalation failure the fast classifier's verdict (when
        available) is returned instead of failing closed - blocking every
        uncertain input because Ollama is cold-loading or briefly down
        made benign traffic unusable.
        """
        with self._stats_lock:
            self._escalated += 1

        logger.debug(
            "Cascade escalating to LlamaGuard (reason=%s, toxic_prob=%s)",
            reason, toxic_prob,
        )

        with self._stats_lock:
            breaker_open = time.monotonic() < self._escalate_retry_at
        if breaker_open and fast_result is not None:
            out = dict(fast_result)
            out["_cascade_path"] = "escalation_skipped_breaker"
            out["_normalized"] = normalized
            if toxic_prob is not None:
                out["_toxic_prob"] = round(float(toxic_prob), 4)
            return out

        try:
            result = await self._slow.classify(
                text=text, stage=stage, categories=categories,
            )
            with self._stats_lock:
                self._escalate_failures = 0
            result["_cascade_path"] = f"escalated_{reason}"
            result["_normalized"] = normalized
            if toxic_prob is not None:
                result["_toxic_prob"] = round(float(toxic_prob), 4)
            return result
        except Exception as e:
            with self._stats_lock:
                self._escalate_failures += 1
                if self._escalate_failures >= self._BREAKER_THRESHOLD:
                    self._escalate_retry_at = time.monotonic() + self._BREAKER_COOLDOWN
                    logger.warning(
                        "Escalation failed %d times in a row - skipping "
                        "escalation for the next %.0fs (fast classifier "
                        "verdicts apply)",
                        self._escalate_failures, self._BREAKER_COOLDOWN,
                    )
            if fast_result is not None:
                logger.warning(
                    "LlamaGuard escalation failed: %r - using the fast "
                    "classifier verdict (safe=%s)",
                    e, fast_result.get("safe"),
                )
                out = dict(fast_result)
                out["_cascade_path"] = "escalation_failed_fast_fallback"
                out["_normalized"] = normalized
                if toxic_prob is not None:
                    out["_toxic_prob"] = round(float(toxic_prob), 4)
                return out
            # No fast verdict to fall back on (the fast classifier itself
            # errored). Honor fail_open: default fail-closed for a security
            # tool; pass only if opted in.
            safe = self._fail_open
            logger.error(
                "LlamaGuard escalation failed: %r - %s",
                e, "failing open (fail_open=True)" if safe else "failing closed",
            )
            return {
                "safe": safe,
                "category": None,
                "categories": [],
                "_cascade_path": "escalation_failed",
                "_normalized": normalized,
            }

    @property
    def stats(self) -> dict[str, Any]:
        """Cascade performance metrics."""
        with self._stats_lock:
            total = max(self._total, 1)
            return {
                "total": self._total,
                "mode": self._mode,
                "fast_resolved": self._fast_resolved,
                "fast_resolved_pct": round(self._fast_resolved / total * 100, 1),
                "fast_blocked": self._fast_blocked,
                "fast_passed": self._fast_passed,
                "keyword_blocked": self._keyword_blocked,
                "escalated": self._escalated,
                "escalated_pct": round(self._escalated / total * 100, 1),
                "safe_threshold": self._safe_threshold,
                "unsafe_threshold": self._unsafe_threshold,
                "normalization_enabled": self._normalize,
                "keyword_gate_enabled": self._keyword_gate,
            }
