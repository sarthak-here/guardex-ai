"""Tests for guardex.conversation — ConversationGuard multi-turn awareness."""

import pytest
import respx

from guardex.guard import Guard
from guardex.conversation import ConversationGuard, Turn
from tests.helpers import SAFE_SCREEN_RESPONSE, UNSAFE_SCREEN_RESPONSE


@pytest.fixture()
def guard_no_injection(api_key, base_url):
    """Guard with client-side injection detection disabled.

    Distinct from conftest.py's `guard` fixture (which has injection_check=True).
    Renamed to avoid shadowing the conftest fixture by accident.
    """
    g = Guard(api_key=api_key, base_url=base_url, injection_check=False)
    yield g
    g.close()


class TestConversationGuard:

    @respx.mock(base_url="http://localhost:8001")
    def test_screen_turn_adds_to_history(self, respx_mock, guard_no_injection):
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=6)
        assert cg.turn_count == 0

        result = cg.screen_turn("user", "Hello")
        assert result.safe is True
        assert cg.turn_count == 1
        assert cg.history[0].role == "user"
        assert cg.history[0].content == "Hello"

    @respx.mock(base_url="http://localhost:8001")
    def test_blocked_turn_not_added_to_history(self, respx_mock, guard_no_injection):
        respx_mock.post("/v1/screen").respond(json=UNSAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=6)
        result = cg.screen_turn("user", "harmful content")
        assert result.blocked is True
        assert cg.turn_count == 0  # blocked turns not added

    @respx.mock(base_url="http://localhost:8001")
    def test_window_limits_history_size(self, respx_mock, guard_no_injection):
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=3)
        for i in range(5):
            cg.screen_turn("user", f"message {i}")

        assert cg.turn_count == 3
        # Oldest messages should be dropped
        assert cg.history[0].content == "message 2"
        assert cg.history[2].content == "message 4"

    @respx.mock(base_url="http://localhost:8001")
    def test_history_prepended_to_screening_payload(self, respx_mock, guard_no_injection):
        """Verify the API receives history + current message."""
        route = respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=6)
        # Add a turn to history
        cg.screen_turn("user", "first message")

        # Now screen a second turn — the request should contain history
        cg.screen_turn("user", "second message")

        # Check the last request body sent to the API
        last_request = route.calls[-1].request
        import json
        body = json.loads(last_request.content)
        # The text should contain the history turn + new message
        assert "[USER] first message" in body["text"]
        assert "second message" in body["text"]

    @respx.mock(base_url="http://localhost:8001")
    def test_assistant_turns_stored_when_enabled(self, respx_mock, guard_no_injection):
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=6, screen_assistant_turns=True)
        cg.screen_turn("user", "Hi")
        cg.screen_turn("assistant", "Hello! How can I help?")

        assert cg.turn_count == 2
        assert cg.history[1].role == "assistant"

    @respx.mock(base_url="http://localhost:8001")
    def test_assistant_turns_not_stored_when_disabled(self, respx_mock, guard_no_injection):
        respx_mock.post("/v1/screen").respond(json=SAFE_SCREEN_RESPONSE)

        cg = ConversationGuard(guard_no_injection, window=6, screen_assistant_turns=False)
        cg.screen_turn("user", "Hi")
        cg.screen_turn("assistant", "Hello!")

        # Assistant turn screened but not stored
        assert cg.turn_count == 1

    def test_reset_clears_history(self, guard_no_injection):
        cg = ConversationGuard(guard_no_injection, window=6)
        cg.add_turn("user", "manual turn")
        assert cg.turn_count == 1
        cg.reset()
        assert cg.turn_count == 0

    def test_add_turn_without_screening(self, guard_no_injection):
        cg = ConversationGuard(guard_no_injection, window=6)
        cg.add_turn("system", "You are a helpful assistant")
        assert cg.turn_count == 1
        assert cg.history[0].role == "system"

    def test_max_payload_truncates_oldest(self, guard_no_injection):
        cg = ConversationGuard(guard_no_injection, window=100, max_payload_chars=50)
        # Add long history
        cg.add_turn("user", "A" * 30)
        cg.add_turn("user", "B" * 30)

        # Build payload for new message — should truncate oldest
        payload = cg._build_payload("new message")
        assert len(payload) <= 50

    def test_repr(self, guard_no_injection):
        cg = ConversationGuard(guard_no_injection, window=4)
        assert "ConversationGuard" in repr(cg)
        assert "window=4" in repr(cg)


class TestTurn:
    def test_to_text(self):
        t = Turn(role="user", content="Hello")
        assert t.to_text() == "[USER] Hello"

    def test_to_text_assistant(self):
        t = Turn(role="assistant", content="Hi there")
        assert t.to_text() == "[ASSISTANT] Hi there"
