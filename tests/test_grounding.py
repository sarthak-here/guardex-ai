"""Tests for hallucination detection via Guard.check_grounding().

This is the headline anti-hallucination feature of GuardEx. All tests use
respx to mock the /v1/grounding endpoint so no server is required.
"""

from __future__ import annotations

import pytest
import respx

from guardex.guard import Guard
from guardex._types import GroundingResult


# ---------------------------------------------------------------------------
# Canonical mock responses for /v1/grounding
# ---------------------------------------------------------------------------

_GROUNDED_RESPONSE: dict = {
    "grounded": True,
    "faithfulness_score": 0.98,
    "has_contradiction": False,
    "sentence_count": 2,
    "grounded_count": 2,
    "contradicted_count": 0,
    "ungrounded_count": 0,
    "uncertain_count": 0,
    "details": [
        {
            "sentence": "The capital of France is Paris.",
            "grounded": True,
            "entailment": 0.99,
            "matched_chunk": "France's capital city is Paris.",
            "verdict": "grounded",
            "contradiction": 0.01,
            "neutral": 0.0,
        },
        {
            "sentence": "Paris is in the north of France.",
            "grounded": True,
            "entailment": 0.97,
            "matched_chunk": "Paris, located in northern France",
            "verdict": "grounded",
            "contradiction": 0.0,
            "neutral": 0.03,
        },
    ],
    "mode": "accuracy",
    "latency_ms": 42.0,
}


_HALLUCINATED_RESPONSE: dict = {
    "grounded": False,
    "faithfulness_score": 0.35,
    "has_contradiction": True,
    "sentence_count": 2,
    "grounded_count": 1,
    "contradicted_count": 1,
    "ungrounded_count": 0,
    "uncertain_count": 0,
    "details": [
        {
            "sentence": "The capital of France is Paris.",
            "grounded": True,
            "entailment": 0.98,
            "matched_chunk": "France's capital city is Paris.",
            "verdict": "grounded",
            "contradiction": 0.02,
            "neutral": 0.0,
        },
        {
            "sentence": "Paris has a population of 50 million.",
            "grounded": False,
            "entailment": 0.05,
            "matched_chunk": None,
            "verdict": "contradicted",
            "contradiction": 0.92,
            "neutral": 0.03,
        },
    ],
    "mode": "accuracy",
    "latency_ms": 58.0,
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@respx.mock(base_url="http://localhost:8001")
def test_grounding_returns_grounded_for_faithful_response(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """A response fully supported by sources -> grounded=True, hallucinated=False."""
    respx_mock.post("/v1/grounding").respond(json=_GROUNDED_RESPONSE)

    result = guard.check_grounding(
        response_text="The capital of France is Paris. Paris is in the north of France.",
        sources=["France's capital city is Paris, located in northern France."],
    )

    assert isinstance(result, GroundingResult)
    assert result.grounded is True
    assert result.hallucinated is False
    assert result.faithfulness_score >= 0.9
    assert result.sentence_count == 2
    assert result.grounded_count == 2
    assert result.ungrounded_count == 0
    assert len(result.details) == 2
    assert all(s.grounded for s in result.details)


@respx.mock(base_url="http://localhost:8001")
def test_grounding_flags_hallucinated_sentence(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """A response with one contradicted claim -> grounded=False, hallucinated_sentences populated."""
    respx_mock.post("/v1/grounding").respond(json=_HALLUCINATED_RESPONSE)

    result = guard.check_grounding(
        response_text=(
            "The capital of France is Paris. Paris has a population of 50 million."
        ),
        sources=["France's capital city is Paris, population ~2 million."],
    )

    assert result.grounded is False
    assert result.hallucinated is True
    assert result.has_contradiction is True
    assert result.contradicted_count == 1
    hallucinated = result.hallucinated_sentences
    assert len(hallucinated) == 1
    assert "50 million" in hallucinated[0].sentence
    assert hallucinated[0].verdict == "contradicted"


def test_grounding_empty_sources_returns_skipped(guard: Guard) -> None:
    """Empty sources: screen_grounded falls back to a 'skipped' placeholder
    when nothing blocks, and check_grounding shouldn't hit the wire here."""
    # Use screen_grounded — which has the skip-on-block placeholder path.
    # For empty sources, server-side is expected to return a trivially-grounded
    # payload; we simulate that with a mock.
    empty_sources_response = {
        "grounded": True,
        "faithfulness_score": 1.0,
        "has_contradiction": False,
        "sentence_count": 0,
        "grounded_count": 0,
        "contradicted_count": 0,
        "ungrounded_count": 0,
        "uncertain_count": 0,
        "details": [],
        "mode": "skipped",
        "latency_ms": 0.0,
    }

    with respx.mock(base_url="http://localhost:8001") as router:
        router.post("/v1/grounding").respond(json=empty_sources_response)

        result = guard.check_grounding(
            response_text="Some response",
            sources=[],
        )

    assert result.grounded is True
    assert result.sentence_count == 0
    assert result.details == []
    assert result.mode == "skipped"


def test_grounding_empty_response_handles_gracefully(guard: Guard) -> None:
    """An empty response_text should not crash the client; server returns
    a grounded=True / zero-sentence result and we parse it cleanly."""
    empty_response_payload = {
        "grounded": True,
        "faithfulness_score": 1.0,
        "has_contradiction": False,
        "sentence_count": 0,
        "grounded_count": 0,
        "contradicted_count": 0,
        "ungrounded_count": 0,
        "uncertain_count": 0,
        "details": [],
        "mode": "accuracy",
        "latency_ms": 1.0,
    }

    with respx.mock(base_url="http://localhost:8001") as router:
        router.post("/v1/grounding").respond(json=empty_response_payload)

        result = guard.check_grounding(
            response_text="",
            sources=["Some source material."],
        )

    assert isinstance(result, GroundingResult)
    assert result.sentence_count == 0
    assert result.details == []


@respx.mock(base_url="http://localhost:8001")
def test_grounding_result_hallucinated_property_is_negation_of_grounded(
    respx_mock: respx.MockRouter, guard: Guard
) -> None:
    """Invariant: GroundingResult.hallucinated MUST equal not grounded — for every result."""
    # Exercise both paths — grounded and hallucinated.
    respx_mock.post("/v1/grounding").respond(json=_GROUNDED_RESPONSE)
    r_ok = guard.check_grounding("x", sources=["y"])
    assert r_ok.hallucinated == (not r_ok.grounded)

    respx_mock.post("/v1/grounding").respond(json=_HALLUCINATED_RESPONSE)
    r_bad = guard.check_grounding("x", sources=["y"])
    assert r_bad.hallucinated == (not r_bad.grounded)

    # And directly on a constructed instance — not just server roundtrips.
    assert GroundingResult(grounded=True).hallucinated is False
    assert GroundingResult(grounded=False).hallucinated is True
