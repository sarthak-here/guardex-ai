"""Tests for guardex.exceptions — message formatting and attributes."""

from __future__ import annotations

import pytest

from guardex.exceptions import GuardExViolation, PIIViolation, GuardExAPIError


class TestGuardExViolation:
    def test_basic_attributes(self) -> None:
        exc = GuardExViolation(stage="input", category="S9")
        assert exc.stage == "input"
        assert exc.category == "S9"
        assert exc.raw_response == ""
        assert exc.description is None

    def test_message_with_category(self) -> None:
        exc = GuardExViolation(stage="input", category="S9")
        msg = str(exc)
        assert "gate=input" in msg
        assert "category=S9" in msg

    def test_message_with_description(self) -> None:
        exc = GuardExViolation(
            stage="tool_input",
            category="S1",
            description="Violent Crimes",
        )
        msg = str(exc)
        assert "gate=tool_input" in msg
        assert "category=S1" in msg
        assert "Violent Crimes" in msg

    def test_message_without_category(self) -> None:
        exc = GuardExViolation(stage="output")
        msg = str(exc)
        assert "gate=output" in msg
        assert "category" not in msg

    def test_is_exception(self) -> None:
        exc = GuardExViolation(stage="input")
        assert isinstance(exc, Exception)

    def test_raw_response_preserved(self) -> None:
        exc = GuardExViolation(stage="input", raw_response="raw data here")
        assert exc.raw_response == "raw data here"


class TestPIIViolation:
    def test_basic_attributes(self) -> None:
        entities = [
            {"label": "ssn", "score": 0.95, "start": 10, "end": 21},
            {"label": "email", "score": 0.99, "start": 0, "end": 16},
        ]
        exc = PIIViolation(stage="input", entities_found=entities)
        assert exc.stage == "input"
        assert exc.entities_found == entities

    def test_message_format(self) -> None:
        entities = [
            {"label": "ssn", "score": 0.95, "start": 10, "end": 21},
        ]
        exc = PIIViolation(stage="input", entities_found=entities)
        msg = str(exc)
        assert "gate=input" in msg
        assert "1 PII entities detected" in msg
        assert "ssn" in msg
        assert "pii_action='mask'" in msg

    def test_multiple_entity_types_sorted(self) -> None:
        entities = [
            {"label": "ssn", "score": 0.95, "start": 0, "end": 5},
            {"label": "email", "score": 0.99, "start": 10, "end": 20},
            {"label": "ssn", "score": 0.90, "start": 30, "end": 40},
        ]
        exc = PIIViolation(stage="output", entities_found=entities)
        msg = str(exc)
        assert "3 PII entities detected" in msg
        # types should be sorted and deduplicated
        assert "email, ssn" in msg

    def test_is_exception(self) -> None:
        exc = PIIViolation(stage="input", entities_found=[])
        assert isinstance(exc, Exception)


class TestGuardExAPIError:
    def test_attributes(self) -> None:
        exc = GuardExAPIError(
            status_code=401,
            error_type="authentication_error",
            message="Invalid API key",
            code="invalid_key",
        )
        assert exc.status_code == 401
        assert exc.error_type == "authentication_error"
        assert exc.message == "Invalid API key"
        assert exc.code == "invalid_key"

    def test_message_format(self) -> None:
        exc = GuardExAPIError(
            status_code=422,
            error_type="validation_error",
            message="Missing field: text",
            code="missing_field",
        )
        msg = str(exc)
        assert "[422]" in msg
        assert "validation_error" in msg
        assert "Missing field: text" in msg

    def test_is_exception(self) -> None:
        exc = GuardExAPIError(
            status_code=500,
            error_type="server_error",
            message="Internal error",
            code="internal",
        )
        assert isinstance(exc, Exception)

    @pytest.mark.parametrize("status", [401, 403, 422, 429, 500, 503])
    def test_various_status_codes(self, status: int) -> None:
        exc = GuardExAPIError(
            status_code=status,
            error_type="error",
            message="test",
            code="test",
        )
        assert exc.status_code == status
        assert f"[{status}]" in str(exc)
