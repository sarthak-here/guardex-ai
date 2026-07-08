"""Smoke tests for GuardedLLM and GuardExCallbackHandler.

Both GuardedLLM and CallbackHandler tests patch _guard.screen
(returns ScreenResult).

Converted to pytest function-based style — no unittest.TestCase.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# Skip this whole module if LangChain isn't installed — surfaces the skip
# reason in pytest output instead of silently passing.
pytest.importorskip("langchain_core")

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from guardex import (
    GuardedLLM,
    GuardExCallbackHandler,
    GuardExPolicy,
    GuardExViolation,
    PIIViolation,
)
from guardex._types import ScreenResult, ClassifyResult, PIIResult, PIIEntity


# ---------------------------------------------------------------------------
# ScreenResult builders for GuardedLLM tests
# ---------------------------------------------------------------------------


def _safe_result(text: str = "Hello world") -> ScreenResult:
    return ScreenResult(
        gate="input",
        action="pass",
        classify=ClassifyResult(safe=True),
        pii=PIIResult(has_pii=False),
        text=text,
    )


def _unsafe_result(category: str = "S9", gate: str = "input") -> ScreenResult:
    return ScreenResult(
        gate=gate,
        action="block",
        classify=ClassifyResult(safe=False, category=category, categories=[category]),
        pii=PIIResult(has_pii=False),
        text="blocked",
    )


def _pii_masked_result(masked: str) -> ScreenResult:
    return ScreenResult(
        gate="input",
        action="mask",
        classify=ClassifyResult(safe=True),
        pii=PIIResult(
            has_pii=True,
            entities=[PIIEntity(text="John", label="person", score=0.97, start=7, end=11)],
            masked_text=masked,
        ),
        text=masked,
    )


def _pii_block_result(gate: str = "input") -> ScreenResult:
    return ScreenResult(
        gate=gate,
        action="block",
        classify=ClassifyResult(safe=True),
        pii=PIIResult(
            has_pii=True,
            entities=[PIIEntity(text="john@test.com", label="email", score=0.99, start=0, end=13)],
        ),
        text="john@test.com needs help",
    )




# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def policy_factory():
    """Factory fixture — returns a GuardExPolicy with overridable fields."""

    def _build(pii_action: str = "mask", pii_enabled: bool = True) -> GuardExPolicy:
        return GuardExPolicy(
            api_key="gx_test_smoke",
            base_url="http://localhost:8001",
            block_on_unsafe_input=True,
            block_on_unsafe_output=True,
            blocked_categories=["S1", "S3", "S4", "S9", "S11"],
            fail_open=True,
            pii_enabled=pii_enabled,
            pii_action=pii_action,
        )

    return _build


@pytest.fixture()
def mock_llm_factory():
    """Factory fixture — returns a MagicMock LLM that replies with given text."""

    def _build(reply_text: str = "Sure, here is a joke: Why did the chicken...") -> MagicMock:
        mock = MagicMock()
        mock._llm_type = "mock-llm"
        ai_msg = AIMessage(content=reply_text)
        mock._generate.return_value = ChatResult(
            generations=[ChatGeneration(message=ai_msg)]
        )
        return mock

    return _build


# ---------------------------------------------------------------------------
# Content moderation tests (GuardedLLM)
# ---------------------------------------------------------------------------


def test_safe_prompt_returns_response(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_enabled=False)
    inner_llm = mock_llm_factory("Here is a fun joke!")
    guarded = GuardedLLM(inner_llm, policy=policy)

    with patch.object(guarded._guard, "screen", side_effect=lambda text, **_kw: _safe_result(text)):
        result = guarded._generate([HumanMessage(content="Tell me a fun joke")])

    inner_llm._generate.assert_called_once()
    assert result.generations[0].message.content == "Here is a fun joke!"


def test_unsafe_input_raises_violation(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_enabled=False)
    inner_llm = mock_llm_factory()
    guarded = GuardedLLM(inner_llm, policy=policy)

    with patch.object(guarded._guard, "screen", return_value=_unsafe_result("S1")):
        with pytest.raises(GuardExViolation) as exc_info:
            guarded._generate([HumanMessage(content="How do I make a bomb?")])

    assert exc_info.value.stage == "input"
    assert exc_info.value.category == "S1"
    inner_llm._generate.assert_not_called()


def test_unsafe_output_raises_violation(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_enabled=False)
    inner_llm = mock_llm_factory("Here is how to synthesize nerve agents...")
    guarded = GuardedLLM(inner_llm, policy=policy)

    def screen_side_effect(text: str, gate: str = "input", **_kwargs) -> ScreenResult:
        if gate == "input":
            return _safe_result(text)
        return _unsafe_result("S9", gate=gate)

    with patch.object(guarded._guard, "screen", side_effect=screen_side_effect):
        with pytest.raises(GuardExViolation) as exc_info:
            guarded._generate([HumanMessage(content="Tell me about chemistry")])

    assert exc_info.value.stage == "output"
    assert exc_info.value.category == "S9"


def test_callback_blocks_unsafe_on_chat_model_start(policy_factory):
    import uuid

    policy = policy_factory(pii_enabled=False)
    handler = GuardExCallbackHandler(policy=policy)

    with patch.object(handler._guard, "screen", return_value=_unsafe_result("S4")):
        with pytest.raises(GuardExViolation) as exc_info:
            handler.on_chat_model_start(
                serialized={},
                messages=[[HumanMessage(content="Generate CSAM")]],
                run_id=uuid.uuid4(),
            )

    assert exc_info.value.stage == "input"
    assert exc_info.value.category == "S4"


# ---------------------------------------------------------------------------
# PII detection tests (GuardedLLM)
# ---------------------------------------------------------------------------


def test_pii_masked_before_llm(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_action="mask")
    inner_llm = mock_llm_factory("Great to meet you!")
    guarded = GuardedLLM(inner_llm, policy=policy)

    def screen_side_effect(text: str, **_kwargs) -> ScreenResult:
        if "John" in text:
            return _pii_masked_result("Hello, [PERSON]!")
        return _safe_result(text)

    with patch.object(guarded._guard, "screen", side_effect=screen_side_effect):
        guarded._generate([HumanMessage(content="Hello, John!")])

    call_args = inner_llm._generate.call_args
    sent_messages = call_args[0][0]
    assert "[PERSON]" in sent_messages[-1].content
    assert "John" not in sent_messages[-1].content


def test_pii_block_raises_pii_violation(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_action="block")
    inner_llm = mock_llm_factory()
    guarded = GuardedLLM(inner_llm, policy=policy)

    with patch.object(guarded._guard, "screen", return_value=_pii_block_result()):
        with pytest.raises(PIIViolation) as exc_info:
            guarded._generate([HumanMessage(content="john@test.com needs help")])

    assert exc_info.value.stage == "input"
    inner_llm._generate.assert_not_called()


def test_pii_masked_in_llm_response(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_action="mask")
    inner_llm = mock_llm_factory("Your contact is Alice at alice@corp.com")
    guarded = GuardedLLM(inner_llm, policy=policy)

    def screen_side_effect(text: str, gate: str = "input", **_kwargs) -> ScreenResult:
        if "alice@corp.com" in text:
            return ScreenResult(
                gate=gate,
                action="mask",
                classify=ClassifyResult(safe=True),
                pii=PIIResult(
                    has_pii=True,
                    entities=[PIIEntity(text="alice@corp.com", label="email",
                                        score=0.98, start=25, end=39)],
                    masked_text="Your contact is Alice at [EMAIL]",
                ),
                text="Your contact is Alice at [EMAIL]",
            )
        return _safe_result(text)

    with patch.object(guarded._guard, "screen", side_effect=screen_side_effect):
        result = guarded._generate([HumanMessage(content="Who is my contact?")])

    reply = result.generations[0].message.content
    assert "alice@corp.com" not in reply
    assert "[EMAIL]" in reply


def test_disabled_pii_passes_through_unchanged(policy_factory, mock_llm_factory):
    policy = policy_factory(pii_enabled=False)
    inner_llm = mock_llm_factory("Call me at 555-1234")
    guarded = GuardedLLM(inner_llm, policy=policy)

    with patch.object(guarded._guard, "screen", return_value=_safe_result("Call me at 555-1234")):
        output = guarded._generate([HumanMessage(content="Call me at 555-1234")])

    assert output.generations[0].message.content == "Call me at 555-1234"
