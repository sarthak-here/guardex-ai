# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""PII detection and masking service using GLiNER.

Uses the centralized model from ``guardex._engine.ml.model_manager`` so the GLiNER
model is loaded once at startup and shared across requests.

No LangChain dependency.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)

DEFAULT_ENTITIES: list[str] = [
    # Personal Info
    "email",
    "phone_number",
    "name",
    "address",
    "ssn",
    "national_id",
    "passport_number",
    "date_of_birth",
    "driver_license",
    # Credentials & Secrets
    "password",
    "user_name",
    "private_key",
    "jwt_token",
    "auth_header",
    "secret",
    # API Keys & Tokens
    "api_key",
    "aws_key",
    "github_token",
    "slack_token",
    "stripe_key",
    "google_api_key",
    "openai_key",
    "twilio_sid",
    # Financial
    "credit_card",
    "bank_account",
    "iban",
    # Network & Infrastructure
    "ip_address",
    "ipv6_address",
    "mac_address",
    "hostname",
    "database_url",
]


def detect(
    text: str,
    entities: list[str] | None = None,
    threshold: float = 0.3,
) -> list[dict[str, Any]]:
    """Run GLiNER entity detection on *text*.

    Parameters
    ----------
    text:
        The input string to scan.
    entities:
        Entity labels to look for (defaults to ``DEFAULT_ENTITIES``).
    threshold:
        Confidence threshold for predictions.

    Returns
    -------
    List of dicts with keys: ``text``, ``label``, ``score``, ``start``, ``end``.
    """
    from guardex._engine.ml.model_manager import get_gliner_model

    model = get_gliner_model()
    if model is None:
        logger.warning("GLiNER model not loaded -- PII detection unavailable.")
        return []

    labels = entities or DEFAULT_ENTITIES
    results = model.predict_entities(text, labels, threshold=threshold)
    return [
        {
            "text": ent["text"],
            "label": ent["label"],
            "score": round(ent["score"], 4),
            "start": ent["start"],
            "end": ent["end"],
        }
        for ent in results
    ]


def mask(text: str, entities_found: list[dict[str, Any]]) -> str:
    """Replace each detected entity span with ``[ENTITY_TYPE]``.

    Processes right-to-left so earlier character indices stay valid
    after each replacement.
    """
    sorted_ents = sorted(entities_found, key=lambda e: e["start"], reverse=True)
    for ent in sorted_ents:
        placeholder = f"[{ent['label'].upper().replace(' ', '_')}]"
        text = text[: ent["start"]] + placeholder + text[ent["end"] :]
    return text


def process(
    text: str,
    entities: list[str] | None = None,
    threshold: float = 0.3,
    action: str = "mask",
) -> dict[str, Any]:
    """Detect PII and optionally mask it.

    Parameters
    ----------
    text:
        The input string to scan.
    entities:
        Entity labels to look for.
    threshold:
        Confidence threshold.
    action:
        ``'mask'`` to return masked text, ``'detect'`` to return
        entities only without modifying text.

    Returns
    -------
    dict with keys: ``has_pii`` (bool), ``entities`` (list),
    ``masked_text`` (str | None), ``original_text`` (str).
    """
    found = detect(text, entities=entities, threshold=threshold)
    has_pii = len(found) > 0

    masked_text = None
    if has_pii and action == "mask":
        masked_text = mask(text, found)

    return {
        "has_pii": has_pii,
        "entities": found,
        "masked_text": masked_text,
        "original_text": text,
    }
