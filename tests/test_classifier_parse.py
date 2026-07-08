# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Guard-model response parsing: LlamaGuard and labelled-verdict formats."""

import pytest

from guardex._engine.services.classifier import _parse_response


@pytest.mark.parametrize(
    "raw, safe, category, categories",
    [
        # LlamaGuard 3 native format
        ("safe", True, None, []),
        ("Safe", True, None, []),
        ("unsafe", False, None, []),
        ("unsafe\nS1,S4", False, "S1", ["S1", "S4"]),
        ("Unsafe\nS9", False, "S9", ["S9"]),
        # Labelled-verdict format (Qwen3Guard and similar generative guards)
        ("Safety: Safe\nCategories: None", True, None, []),
        ("Safety: Unsafe\nCategories: Violent", False, None, []),
        ("Safety: Unsafe\nCategories: S9", False, "S9", ["S9"]),
        ("Safety: Unsafe\nCategories: S1, S11", False, "S1", ["S1", "S11"]),
        ("safety: unsafe", False, None, []),
        # Other label keywords a future model might use
        ("Verdict: Safe", True, None, []),
        ("Result: Unsafe\nS4", False, "S4", ["S4"]),
        # Markdown / punctuation decoration around the verdict
        ("**Unsafe**\nS1", False, "S1", ["S1"]),
        ("Safe.", True, None, []),
        # S-code on the same line as the verdict
        ("unsafe: S1", False, "S1", ["S1"]),
        # Non-S-code category names are dropped, never propagated
        ("unsafe\nViolent Crimes, S3", False, "S3", ["S3"]),
        # Duplicate S-codes collapse, order preserved
        ("unsafe\nS3, S1, S3", False, "S3", ["S3", "S1"]),
        # Bare S-code fallback anywhere in the reply
        ("The message violates S11 policy", False, "S11", ["S11"]),
        # Ambiguous replies fail closed
        ("I think this is fine", False, None, []),
        ("Safety: Controversial\nCategories: None", False, None, []),
        ("", False, None, []),
    ],
)
def test_parse_response(raw, safe, category, categories):
    result = _parse_response(raw)
    assert result["safe"] is safe
    assert result["category"] == category
    assert result["categories"] == categories
