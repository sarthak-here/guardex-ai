"""Tests for guardex._types — dataclass types, Gate mapping, frozen behaviour."""

from __future__ import annotations

import pytest

from guardex._types import (
    ScreenResult,
    ClassifyResult,
    PIIResult,
    PIIEntity,
    gate_to_stage,
    output_gate_for,
    CATEGORY_DESCRIPTIONS,
    ALL_CATEGORIES,
    DEFAULT_BLOCKED,
    DEFAULT_PII_ENTITIES,
)


# ---------------------------------------------------------------------------
# Gate mapping
# ---------------------------------------------------------------------------

class TestGateToStage:
    """gate_to_stage maps every known gate to the correct server stage."""

    @pytest.mark.parametrize(
        "gate, expected_stage",
        [
            ("input", "input"),
            ("prompt", "prompt"),
            ("stream", "stream"),
            ("output", "output"),
            ("tool_input", "tool_input"),
            ("tool_output", "tool_output"),
            ("retrieval_query", "retrieval_query"),
            ("retrieval_result", "retrieval_result"),
        ],
    )
    def test_known_gates(self, gate: str, expected_stage: str) -> None:
        assert gate_to_stage(gate) == expected_stage

    def test_unknown_gate_returns_itself(self) -> None:
        assert gate_to_stage("custom_gate") == "custom_gate"


class TestOutputGateFor:
    """output_gate_for returns the matching output gate for an input gate."""

    @pytest.mark.parametrize(
        "gate, expected_output",
        [
            ("input", "output"),
            ("tool_input", "tool_output"),
            ("retrieval_query", "retrieval_result"),
            ("prompt", "output"),
        ],
    )
    def test_known_mappings(self, gate: str, expected_output: str) -> None:
        assert output_gate_for(gate) == expected_output

    def test_unknown_gate_defaults_to_output(self) -> None:
        assert output_gate_for("something_random") == "output"


# ---------------------------------------------------------------------------
# PIIEntity
# ---------------------------------------------------------------------------

class TestPIIEntity:
    def test_creation(self) -> None:
        entity = PIIEntity(text="123-45-6789", label="ssn", score=0.95, start=10, end=21)
        assert entity.text == "123-45-6789"
        assert entity.label == "ssn"
        assert entity.score == 0.95
        assert entity.start == 10
        assert entity.end == 21

    def test_frozen(self) -> None:
        entity = PIIEntity(text="x", label="email", score=0.9, start=0, end=1)
        with pytest.raises(AttributeError):
            entity.text = "y"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = PIIEntity(text="x", label="email", score=0.9, start=0, end=1)
        b = PIIEntity(text="x", label="email", score=0.9, start=0, end=1)
        assert a == b

    def test_inequality(self) -> None:
        a = PIIEntity(text="x", label="email", score=0.9, start=0, end=1)
        b = PIIEntity(text="y", label="email", score=0.9, start=0, end=1)
        assert a != b


# ---------------------------------------------------------------------------
# ClassifyResult
# ---------------------------------------------------------------------------

class TestClassifyResult:
    def test_safe_defaults(self) -> None:
        r = ClassifyResult(safe=True)
        assert r.safe is True
        assert r.category is None
        assert r.categories == []
        assert r.confidence == 1.0
        assert r.description is None

    def test_unsafe_with_category(self) -> None:
        r = ClassifyResult(safe=False, category="S9", categories=["S9"], description="Weapons")
        assert r.safe is False
        assert r.category == "S9"
        assert r.categories == ["S9"]
        assert r.description == "Weapons"

    def test_frozen(self) -> None:
        r = ClassifyResult(safe=True)
        with pytest.raises(AttributeError):
            r.safe = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PIIResult
# ---------------------------------------------------------------------------

class TestPIIResult:
    def test_no_pii(self) -> None:
        r = PIIResult(has_pii=False)
        assert r.has_pii is False
        assert r.entities == []
        assert r.masked_text is None

    def test_with_entities(self) -> None:
        e = PIIEntity(text="abc", label="name", score=0.8, start=0, end=3)
        r = PIIResult(has_pii=True, entities=[e], masked_text="[NAME]")
        assert r.has_pii is True
        assert len(r.entities) == 1
        assert r.masked_text == "[NAME]"

    def test_frozen(self) -> None:
        r = PIIResult(has_pii=False)
        with pytest.raises(AttributeError):
            r.has_pii = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ScreenResult
# ---------------------------------------------------------------------------

class TestScreenResult:
    def test_safe_pass(self) -> None:
        r = ScreenResult(
            gate="input",
            action="pass",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text="hello",
        )
        assert r.safe is True
        assert r.blocked is False
        assert r.gate == "input"
        assert r.action == "pass"
        assert r.latency_ms == 0.0
        assert r.request_id is None

    def test_blocked(self) -> None:
        r = ScreenResult(
            gate="input",
            action="block",
            classify=ClassifyResult(safe=False, category="S1"),
            pii=PIIResult(has_pii=False),
            text="bad",
        )
        assert r.safe is False
        assert r.blocked is True

    def test_mask_is_safe(self) -> None:
        r = ScreenResult(
            gate="input",
            action="mask",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=True, masked_text="[MASKED]"),
            text="[MASKED]",
        )
        assert r.safe is True
        assert r.blocked is False

    def test_frozen(self) -> None:
        r = ScreenResult(
            gate="input",
            action="pass",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text="hello",
        )
        with pytest.raises(AttributeError):
            r.gate = "output"  # type: ignore[misc]

    def test_latency_and_request_id(self) -> None:
        r = ScreenResult(
            gate="output",
            action="pass",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text="hello",
            latency_ms=42.5,
            request_id="req-abc",
        )
        assert r.latency_ms == 42.5
        assert r.request_id == "req-abc"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_all_categories_length(self) -> None:
        assert len(ALL_CATEGORIES) == 14

    def test_default_blocked_subset(self) -> None:
        for cat in DEFAULT_BLOCKED:
            assert cat in ALL_CATEGORIES

    def test_category_descriptions_keys(self) -> None:
        for cat in ALL_CATEGORIES:
            assert cat in CATEGORY_DESCRIPTIONS

    def test_default_pii_entities_non_empty(self) -> None:
        assert len(DEFAULT_PII_ENTITIES) > 0
        assert "ssn" in DEFAULT_PII_ENTITIES
        assert "email" in DEFAULT_PII_ENTITIES
