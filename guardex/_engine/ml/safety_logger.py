# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Structured JSON logging for safety classification decisions.

One JSON line per decision. The original text is hashed (SHA-256, first
16 hex chars) so the audit trail never carries plaintext PII. Fields:
``timestamp``, ``text_hash``, ``text_length``, ``stage``, ``cascade_path``,
``safe``, ``category``, ``categories``, ``confidence``, ``latency_ms``,
``normalized``, ``keyword_matched``, ``validation_passed``.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any


_safety_logger = logging.getLogger("guardex.safety_audit")


def _hash_text(text: str) -> str:
    """SHA-256 hash of text - for audit trail without storing PII."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def log_safety_decision(
    text: str,
    result: dict[str, Any],
    cascade_path: str,
    latency_ms: int,
    stage: str = "input",
    normalized: bool = False,
    keyword_matched: bool = False,
    validation_passed: bool = True,
) -> None:
    """Log a structured safety classification decision.

    Parameters
    ----------
    text : str
        Original input text (will be hashed, never stored in plaintext).
    result : dict
        Classification result with 'safe', 'category', 'categories' keys.
    cascade_path : str
        Which cascade layer made the decision.
    latency_ms : int
        Total classification latency in milliseconds.
    stage : str
        'input' or 'output'.
    normalized : bool
        Whether text normalization modified the input.
    keyword_matched : bool
        Whether the keyword gate fired.
    validation_passed : bool
        Whether input validation passed.
    """
    # Prefer the public ``confidence`` field; fall back to the legacy
    # ``_toxic_prob`` internal key for older provider responses.
    confidence = result.get("confidence")
    if confidence is None:
        confidence = result.get("_toxic_prob")

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "text_hash": _hash_text(text),
        "text_length": len(text),
        "stage": stage,
        "cascade_path": cascade_path,
        "safe": result.get("safe", True),
        "category": result.get("category"),
        "categories": result.get("categories", []),
        "confidence": confidence,
        "latency_ms": latency_ms,
        "normalized": normalized,
        "keyword_matched": keyword_matched,
        "validation_passed": validation_passed,
    }

    _safety_logger.info(json.dumps(entry, separators=(",", ":")))
