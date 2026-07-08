# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""LlamaGuardClassifier - direct LlamaGuard-style classification over the API.

For the recommended interface use :class:`guardex.Guard`; this class exists
for callers that want to invoke the classify endpoint directly without the
PII / scope pipeline. It returns the SDK's public :class:`ClassifyResult`
(from :mod:`guardex._types`) so callers see the same shape everywhere.

Note: this class talks to the GuardEx server. In zero-config local mode
(``Guard()`` with no api_key/base_url), use ``Guard.classify(...)``
instead - that runs through ``LocalRunner``.
"""
from __future__ import annotations

import logging
from typing import Any, List

from ._types import CATEGORY_DESCRIPTIONS, ClassifyResult  # noqa: F401  (re-export for back-compat)
from .policy import GuardExPolicy

logger = logging.getLogger(__name__)


class LlamaGuardClassifier:
    """Classify messages against a configured GuardEx server."""

    def __init__(self, policy: GuardExPolicy) -> None:
        self._policy = policy
        from .client import GuardExClient
        # Let exceptions propagate so callers see invalid API key / network
        # configuration immediately instead of getting a silently-disabled
        # classifier that always returns safe=True.
        self._client = GuardExClient(
            api_key=policy.api_key,
            base_url=policy.base_url,
            timeout=policy.timeout,
            fail_open=policy.fail_open,
        )

    def classify(
        self,
        messages: List[Any],
        stage: str = "input",
    ) -> ClassifyResult:
        """Classify a list of messages; returns the first unsafe result.

        Accepts plain strings, dicts with a ``content`` key
        (``{"role": ..., "content": ...}``), and objects with a
        ``.content`` attribute (LangChain messages).
        """
        # Screen each message individually rather than " ".join-ing them:
        # joining dilutes the classifier signal when only one message is unsafe.
        worst: ClassifyResult = ClassifyResult(safe=True)
        for msg in messages:
            if isinstance(msg, str):
                content: Any = msg
            elif isinstance(msg, dict):
                content = msg.get("content")
            else:
                content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content.strip():
                if content is None:
                    logger.warning(
                        "LlamaGuardClassifier.classify skipping message with no "
                        "extractable content (type=%s)", type(msg).__name__,
                    )
                continue
            try:
                result = self._client.classify(
                    content,
                    stage=stage,
                    categories=self._policy.blocked_categories,
                )
                cr = ClassifyResult(
                    safe=result.get("safe", True),
                    category=result.get("category"),
                    categories=result.get("categories", []),
                    confidence=result.get("confidence", 1.0),
                    description=result.get("description"),
                )
            except Exception as e:
                logger.warning(
                    "LlamaGuardClassifier.classify failed (stage=%s, fail_open=%s): %s",
                    stage, self._policy.fail_open, e,
                )
                if not self._policy.fail_open:
                    raise
                cr = ClassifyResult(safe=True)

            # Worst-severity wins: any unsafe result trumps a safe one.
            if not cr.safe and worst.safe:
                worst = cr
        return worst
