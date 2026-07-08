# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Exceptions raised by the GuardEx SDK.

All exceptions are framework-independent - no langchain, no pydantic imports.
"""

from __future__ import annotations

from typing import List, Optional


class GuardExViolation(Exception):
    """Raised when content is classified as unsafe.

    Attributes
    ----------
    stage:       Gate where the violation occurred (e.g. 'input', 'tool_input').
    category:    Safety category code (e.g. 'S1', 'S9').
    description: Human-readable description of the violation.
    """

    def __init__(
        self,
        stage: str,
        category: Optional[str] = None,
        raw_response: str = "",
        description: Optional[str] = None,
    ) -> None:
        self.stage = stage
        self.category = category
        self.raw_response = raw_response
        self.description = description

        # Build a helpful error message
        parts = [f"GuardEx blocked at gate={stage}"]
        if category:
            parts.append(f"category={category}")
        if description:
            parts.append(f"({description})")
        super().__init__(", ".join(parts))


class PIIViolation(GuardExViolation):
    """Raised when PII is detected and policy is set to block.

    Inherits from GuardExViolation so ``except GuardExViolation`` catches
    both safety classification blocks and PII blocks.

    Attributes
    ----------
    stage:          Gate where PII was detected.
    entities_found: List of dicts with keys: label, score, start, end.
    """

    def __init__(self, stage: str, entities_found: List[dict]) -> None:
        self.entities_found = entities_found
        if entities_found:
            types = sorted(set(e.get("label", "unknown") for e in entities_found))
            description = (
                f"{len(entities_found)} PII entities detected "
                f"(types: {', '.join(types)}). "
                f"Use pii_action='mask' to redact instead of blocking."
            )
        else:
            description = (
                "PII detected. Use pii_action='mask' to redact instead of blocking."
            )
        super().__init__(stage=stage, category="pii", description=description)


class GuardExAPIError(Exception):
    """Raised on HTTP errors from the GuardEx API.

    Attributes
    ----------
    status_code: HTTP status code (401, 403, 422, 429, 500, etc.)
    error_type:  Error type string from the API response.
    message:     Human-readable error message.
    code:        Machine-readable error code.
    """

    def __init__(
        self,
        status_code: int,
        error_type: str,
        message: str,
        code: str,
    ) -> None:
        self.status_code = status_code
        self.error_type = error_type
        self.message = message
        self.code = code
        super().__init__(f"[{status_code}] {error_type}: {message}")
