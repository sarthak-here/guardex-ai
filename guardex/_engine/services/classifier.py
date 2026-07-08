# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""LlamaGuard 3 safety classifier service.

Calls Ollama over HTTP -- POST {ollama_url}/api/chat.

No LangChain dependency. Accepts plain text and returns structured dicts.
"""

from __future__ import annotations

import logging
import re
from typing import Literal

import httpx

from guardex._engine.settings import local_settings as settings
from guardex._types import CATEGORY_DESCRIPTIONS

logger = logging.getLogger(__name__)

# Shared HTTP client - created once, reused across requests for connection pooling.
_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared httpx client, creating it on first use."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0,                               # Fast fail on connection
                read=float(settings.classifier_timeout),   # Model inference time
                write=5.0,
                pool=10.0,
            ),
            limits=httpx.Limits(
                max_connections=20,
                max_keepalive_connections=10,
                keepalive_expiry=300,  # 5 min keep-alive to Ollama
            ),
        )
    return _http_client

Stage = Literal["input", "output"]

# All categories by default - CATEGORY_DESCRIPTIONS is the single source of
# truth in guardex._types.
DEFAULT_CATEGORIES: list[str] = list(CATEGORY_DESCRIPTIONS.keys())


def _build_prompt(
    text: str,
    stage: Stage,
    categories: list[str] | None = None,
) -> str:
    """Build the LlamaGuard 3 conversation template.

    LlamaGuard 3 expects a specific chat template with special tokens:

        <|begin_of_text|><|start_header_id|>user<|end_header_id|>
        Task: Check if there is unsafe content ...
        <|eot_id|><|start_header_id|>assistant<|end_header_id|>
    """
    cats = categories or DEFAULT_CATEGORIES
    categories_block = "\n".join(
        f"{code}: {CATEGORY_DESCRIPTIONS.get(code, code)}" for code in cats
    )

    if stage == "input":
        task_description = (
            "Check if there is unsafe content in the 'User' message according "
            "to our safety policy with the below categories."
        )
        check_target = f"<BEGIN USER MESSAGE>\nUser: {text}\n<END USER MESSAGE>"
    else:
        task_description = (
            "Check if there is unsafe content in the 'Agent' messages according "
            "to our safety policy with the below categories."
        )
        check_target = f"<BEGIN CONVERSATION>\nAgent: {text}\n<END CONVERSATION>"

    prompt = (
        "<|begin_of_text|>"
        "<|start_header_id|>user<|end_header_id|>\n\n"
        f"Task: {task_description}\n\n"
        "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
        f"{categories_block}\n"
        "<END UNSAFE CONTENT CATEGORIES>\n\n"
        f"{check_target}\n\n"
        "Provide your safety assessment for the above content:\n"
        "- First line must read 'safe' or 'unsafe'.\n"
        "- If unsafe, a second line must include a comma-separated list of violated categories.\n"
        "<|eot_id|>"
        "<|start_header_id|>assistant<|end_header_id|>"
    )
    return prompt


async def _call_ollama(prompt: str, model_name: str | None = None) -> str:
    """POST to Ollama /api/chat endpoint."""
    url = settings.ollama_url.rstrip("/") + "/api/chat"
    payload = {
        "model": model_name or settings.ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    client = get_http_client()
    resp = await client.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    return data["message"]["content"].strip()




def _extract_scodes(raw: str) -> list[str]:
    """Ordered, de-duplicated S-codes (S1-S14) found anywhere in the text."""
    seen: dict[str, None] = {}
    for m in re.findall(r"\bS\d{1,2}\b", raw, re.IGNORECASE):
        seen.setdefault(m.upper(), None)
    return list(seen)


def _parse_response(raw: str) -> dict:
    """Parse a guard model's plain-text verdict into a structured dict.

    Format-tolerant by design so a new guard model does not require code
    changes. The prompt asks for a first line of ``safe``/``unsafe``; this
    also accepts a labelled verdict (``Safety: Unsafe``) and reads S-codes
    from anywhere in the reply, whatever surrounds them. Only S-codes are
    propagated - model-specific category names (``Violent``) are dropped so
    downstream policy stays on the S1-S14 axis.

    The safety bias is asymmetric: only an explicit ``safe`` verdict passes;
    every unrecognized reply is treated as UNSAFE. A model in an unknown
    format therefore over-blocks (visible, safe to catch) rather than
    letting unsafe content through (silent, dangerous).

    Returns
    -------
    dict with keys: safe (bool), category (str|None), categories (list[str])
    """
    first_line = raw.strip().lower().split("\n")[0].strip()

    # Some generative guards label the verdict ("Safety: Unsafe") instead of
    # emitting LlamaGuard's bare "safe"/"unsafe". Strip a leading label.
    if ":" in first_line:
        head, _, tail = first_line.partition(":")
        if head.strip() in ("safety", "verdict", "result", "label", "assessment"):
            first_line = tail.strip()

    # Strip markdown/punctuation decoration around the verdict token
    # ("**Unsafe**", "Safe.") so it still matches.
    first_line = first_line.strip(" .!*_`\"'")

    if first_line == "safe":
        return {"safe": True, "category": None, "categories": []}

    if first_line.startswith("unsafe"):
        codes = _extract_scodes(raw)
        return {"safe": False, "category": codes[0] if codes else None, "categories": codes}

    # No recognized verdict. A bare S-code anywhere still means unsafe.
    codes = _extract_scodes(raw)
    if codes:
        return {"safe": False, "category": codes[0], "categories": codes}

    # Unrecognized reply - fail closed and surface it so operators can add
    # the format (a test case in tests/test_classifier_parse.py) if it recurs.
    logger.warning(
        "Guard model returned an unrecognized response: %r - treating as UNSAFE", raw
    )
    return {"safe": False, "category": None, "categories": []}


async def classify(
    text: str,
    stage: Stage = "input",
    categories: list[str] | None = None,
    fail_open: bool | None = None,
    model_name: str | None = None,
) -> dict:
    """Classify text for safety using LlamaGuard 3.

    Parameters
    ----------
    text:
        The text to classify.
    stage:
        ``'input'`` (user message) or ``'output'`` (AI response).
    categories:
        List of category codes to check (e.g. ``['S1', 'S3']``).
        Defaults to all S1-S14.
    fail_open:
        Override for ``settings.fail_open``. If True, return safe on
        backend errors. If False, raise.

    Returns
    -------
    dict with keys: ``safe`` (bool), ``category`` (str|None),
    ``categories`` (list[str]).
    """
    should_fail_open = fail_open if fail_open is not None else settings.fail_open
    prompt = _build_prompt(text, stage, categories)

    try:
        raw = await _call_ollama(prompt, model_name=model_name)
    except Exception as exc:
        if should_fail_open:
            logger.warning("LlamaGuard call failed (fail_open=True): %s", exc)
            return {"safe": True, "category": None, "categories": []}
        raise

    return _parse_response(raw)
