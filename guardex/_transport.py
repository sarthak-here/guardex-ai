# SPDX-License-Identifier: Apache-2.0
"""Shared transport helpers for GuardExClient and AsyncGuardExClient.

The two HTTP clients are 95% identical: same payload shapes, same retry
semantics, same fail-open dictionaries.  Anything that doesn't intrinsically
need ``await`` lives here so the sync and async classes stay aligned.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from ._types import resolve_categories

logger = logging.getLogger(__name__)


# Header names forwarded to the server for the policy/context audit trail.
HEADER_CONTEXT    = "X-GuardEx-Context"
HEADER_POLICY     = "X-GuardEx-Policy-Hash"
HEADER_SESSION    = "X-GuardEx-Session-Id"
HEADER_REQUEST_ID = "X-GuardEx-Request-Id"

# Default messages used when the server response body is missing.
DEFAULT_API_ERROR_MESSAGES: Dict[int, str] = {
    401: "Invalid or missing API key. Set GUARDEX_API_KEY or pass api_key=.",
    403: "Access forbidden. Check your API key permissions.",
    404: "Endpoint not found. Check that base_url points at a GuardEx server.",
    422: "Request validation failed. Check your request payload.",
}


def build_screen_payload(
    text: str,
    stage: str,
    pii_action: Literal["mask", "block", "none"],
    pii_threshold: float,
    cascade_mode: str,
    audit_log: bool,
    categories: Optional[List[str]],
    pii_entities: Optional[List[str]],
    scope_topics: Optional[List[str]] = None,
    scope_utterances: Optional[Dict[str, List[str]]] = None,
    scope_examples: Optional[List[str]] = None,
    scope_width: str = "moderate",
    scope_threshold: Optional[float] = None,
    scope_alpha: float = 0.0,
) -> Dict[str, Any]:
    """Build the JSON body for ``POST /v1/screen``.

    Identical between sync and async client paths.
    """
    payload: Dict[str, Any] = {
        "text": text,
        "stage": stage,
        "pii_action": pii_action,
        "pii_threshold": pii_threshold,
        "cascade_mode": cascade_mode,
        "prompt_guard": stage == "input",
    }
    if audit_log:
        payload["audit_log"] = True
    if categories:
        payload["categories"] = resolve_categories(categories)
    if pii_entities:
        payload["pii_entities"] = pii_entities

    if scope_topics:
        payload["scope_topics"] = scope_topics
        if scope_utterances:
            payload["scope_utterances"] = scope_utterances
        if scope_examples:
            payload["scope_examples"] = scope_examples
        payload["scope_width"] = scope_width
        if scope_threshold is not None:
            payload["scope_threshold"] = scope_threshold
        if scope_alpha:
            payload["scope_alpha"] = scope_alpha

    return payload


def build_screen_batch_payload(
    texts: List[str],
    stage: str,
    pii_action: Literal["mask", "block", "none"],
    pii_threshold: float,
    cascade_mode: str,
    categories: Optional[List[str]],
    pii_entities: Optional[List[str]],
) -> Dict[str, Any]:
    """Build the JSON body for ``POST /v1/screen/batch``."""
    resolved_cats = resolve_categories(categories) if categories else None
    return {
        "requests": [
            {
                "text": t,
                "stage": stage,
                "pii_action": pii_action,
                "pii_threshold": pii_threshold,
                "cascade_mode": cascade_mode,
                **({"categories": resolved_cats} if resolved_cats else {}),
                **({"pii_entities": pii_entities} if pii_entities else {}),
            }
            for t in texts
        ]
    }


def screen_failopen_shape(text: str) -> Dict[str, Any]:
    """Return the ``_fail_open`` response body shape for ``/v1/screen``."""
    return {
        "pii": {"has_pii": False, "entities": []},
        "classify": {"safe": True, "category": None, "categories": []},
        "text": text,
        "_fail_open": True,
    }


def grounding_failopen_shape(mode: Optional[str]) -> Dict[str, Any]:
    """Return the ``_fail_open`` response shape for ``/v1/grounding``.

    Defaults to ``grounded=False`` so a server outage cannot let a
    hallucinated response slip through as ``grounded=True`` - that would
    be a real safety regression for any caller using grounding to gate
    user-visible output.
    """
    return {
        "grounded": False,
        "faithfulness_score": 0.0,
        "has_contradiction": False,
        "sentence_count": 0,
        "grounded_count": 0,
        "contradicted_count": 0,
        "ungrounded_count": 0,
        "uncertain_count": 0,
        "details": [],
        "mode": mode or "accuracy",
        "_fail_open": True,
    }


def base_headers(sdk_version: str, api_key: Optional[str]) -> Dict[str, str]:
    """Build the constant HTTP headers attached to every request."""
    headers: Dict[str, str] = {
        "User-Agent": f"guardex-python/{sdk_version}",
        "X-SDK-Version": sdk_version,
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def parse_pii_blocked_error(exc, stage: str):
    """If a GuardExAPIError signals a PII-blocked response, raise PIIViolation."""
    from .exceptions import GuardExAPIError, PIIViolation

    if isinstance(exc, GuardExAPIError) and exc.code == "pii_blocked":
        raise PIIViolation(stage=stage, entities_found=[]) from exc
