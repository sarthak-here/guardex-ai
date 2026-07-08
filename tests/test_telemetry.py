"""Tests for guardex.telemetry — OTel spans and audit logging."""

import logging

from guardex.telemetry import (
    screening_span,
    record_result,
    emit_audit_log,
    otel_available,
)
from guardex._types import (
    ScreenResult, ClassifyResult, PIIResult, ScopeResult,
)


class TestScreeningSpan:
    """Test the screening_span context manager."""

    def test_yields_none_without_otel(self):
        """screening_span yields a usable context regardless of OTel availability.

        When OTel is NOT installed, the span MUST be None.
        When OTel IS installed, the span must be a non-None tracing span.
        In both cases, exiting the context manager must not raise.
        """
        with screening_span("input") as span:
            if otel_available():
                # OTel installed -> real span object with set_attribute
                assert span is not None
                assert hasattr(span, "set_attribute")
            else:
                # OTel missing -> span MUST be None (no-op path)
                assert span is None

    def test_context_manager_does_not_raise(self):
        """Span context manager exits cleanly and yields a value consistent with OTel state."""
        with screening_span("output") as span:
            if otel_available():
                assert span is not None
            else:
                assert span is None


class TestRecordResult:
    """Test record_result with span=None (no-op path)."""

    def test_noop_with_none_span(self):
        result = ScreenResult(
            gate="input",
            action="pass",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text="test",
            latency_ms=42.0,
            request_id="req-123",
        )
        # Should not raise
        record_result(None, result)

    def test_noop_with_blocked_result(self):
        result = ScreenResult(
            gate="input",
            action="block",
            classify=ClassifyResult(safe=False, category="S9"),
            pii=PIIResult(has_pii=False),
            text="bad text",
            latency_ms=100.0,
        )
        record_result(None, result)

    def test_noop_with_scope_result(self):
        result = ScreenResult(
            gate="input",
            action="block",
            classify=ClassifyResult(safe=True),
            pii=PIIResult(has_pii=False),
            text="off topic",
            scope=ScopeResult(allowed=False, matched_topic="banking"),
            latency_ms=5.0,
        )
        record_result(None, result)


class TestEmitAuditLog:
    """Test emit_audit_log writes to the guardex.audit logger."""

    def test_emits_info_log(self, caplog):
        with caplog.at_level(logging.INFO, logger="guardex.audit"):
            emit_audit_log(
                gate="input",
                action="block",
                safe=False,
                category="S9",
                request_id="req-abc",
                latency_ms=142.3,
                pii_detected=True,
                pii_count=2,
            )

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert "GUARDEX_AUDIT" in record.message
        assert "input" in record.message
        assert "block" in record.message

    def test_detailed_includes_preview(self, caplog):
        with caplog.at_level(logging.INFO, logger="guardex.audit"):
            emit_audit_log(
                gate="output",
                action="pass",
                safe=True,
                category=None,
                request_id="req-xyz",
                latency_ms=50.0,
                pii_detected=False,
                pii_count=0,
                detailed=True,
                text_preview="Hello world this is a test" * 20,
            )

        record = caplog.records[0]
        assert "text_preview" in record.message
        # Preview should be truncated at 200 chars
        # The log format includes the dict repr, so just check it exists

    def test_no_preview_when_not_detailed(self, caplog):
        with caplog.at_level(logging.INFO, logger="guardex.audit"):
            emit_audit_log(
                gate="input",
                action="pass",
                safe=True,
                category=None,
                request_id=None,
                latency_ms=10.0,
                pii_detected=False,
                pii_count=0,
                detailed=False,
                text_preview=None,
            )

        record = caplog.records[0]
        assert "text_preview" not in record.message


class TestOtelAvailable:
    def test_returns_bool(self):
        result = otel_available()
        assert isinstance(result, bool)
