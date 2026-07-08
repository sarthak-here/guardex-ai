# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Client-side prompt-injection and jailbreak detection.

LlamaGuard's S1-S14 taxonomy classifies content (violence, PII, etc.) and
does not cover meta-level attacks against the system prompt itself:
instruction overrides, DAN-style jailbreaks, ``<|system|>`` token
injection, and indirect injection via RAG documents.

This module catches those with a regex pass that runs before the screen
call when ``Guard(injection_check=True)`` (the default). Model-based
detection runs in the cascade or on the server.

Usage::

    from guardex.injection import InjectionDetector

    detector = InjectionDetector()
    result = detector.scan("Ignore all previous instructions and...")
    if result.detected:
        print(result.matched_pattern, result.severity)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


# Each entry: (pattern_string, human_label, severity: "high"|"medium"|"low")
_RAW_PATTERNS: list[tuple[str, str, str]] = [
    # Direct instruction override
    (
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?",
        "instruction_override",
        "high",
    ),
    (
        r"(?i)disregard\s+(your\s+)?(previous\s+|all\s+)?instructions?",
        "instruction_override",
        "high",
    ),
    (
        r"(?i)forget\s+(your\s+)?(previous\s+|all\s+)?instructions?",
        "instruction_override",
        "high",
    ),
    (
        r"(?i)override\s+(your\s+)?(previous\s+|all\s+)?instructions?",
        "instruction_override",
        "high",
    ),
    (
        r"(?i)you\s+(must\s+)?now\s+(ignore|disregard|forget)\s+(all\s+)?(rules|guidelines|instructions?|restrictions?|constraints?)",
        "instruction_override",
        "high",
    ),

    # Jailbreak personas. The bare token "DAN" is not enough - require
    # "do anything now" context to avoid false positives on the acronym.
    (
        r"(?i)\bdo\s+anything\s+now\b",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)\bDAN\s+(mode|jailbreak|prompt)\b",
        "jailbreak_persona",
        "high",
    ),
    # `\S+(\s+\S+){0,N}` form is ReDoS-safe; `.{0,N}` is not on crafted input.
    (
        r"(?i)act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?an?\s+\S+(?:\s+\S+){0,8}\s+(?:without\s+(?:restrictions?|guidelines?|rules?|ethics?)|uncensored|unfiltered)",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)pretend\s+(?:you\s+are|to\s+be)\s+\S+(?:\s+\S+){0,8}\s+(?:AI|LLM|bot|model|assistant)\S*(?:\s+\S+){0,4}\s+(?:no\s+restrictions?|without\s+limits?|no\s+rules?)",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)you\s+are\s+now\s+\S+(?:\s+\S+){0,8}\s+(?:unrestricted|without\s+(?:rules?|constraints?|ethics?|guidelines?)|unfiltered)",
        "jailbreak_persona",
        "high",
    ),

    # Role-play bypass
    (
        r"(?i)let['']?s\s+(?:role.?play|pretend|imagine)\s+\S+(?:\s+\S+){0,12}\s+(?:no\s+restrictions?|without\s+(?:rules?|limits?)|can\s+say\s+anything)",
        "roleplay_bypass",
        "medium",
    ),
    (
        r"(?i)in\s+this\s+(?:hypothetical|fictional|imaginary|story)\s+(?:scenario|world|universe)\S*(?:\s+\S+){0,15}\s+(?:no\s+restrictions?|without\s+limits?|unrestricted|bypass)",
        "roleplay_bypass",
        "medium",
    ),

    # System-prompt / token injection
    (r"<\|system\|>",                  "token_injection", "high"),
    (r"<\|im_start\|>\s*system",       "token_injection", "high"),
    (r"(?i)\[SYSTEM\][^\[]{0,500}\[END\s*SYSTEM\]", "token_injection", "high"),
    (r"(?i)###\s*SYSTEM\s*###",        "token_injection", "high"),
    (r"(?i)###\s*INSTRUCTION[S]?\s*###","token_injection", "high"),
    (r"(?i)<<SYS>>[^<]{0,500}<</SYS>>", "token_injection", "high"),

    # Extended jailbreak personas. Registered after token-injection so an
    # input containing both resolves ``matched_pattern`` to ``token_injection``
    # - that ordering is part of the public contract.
    (
        r"(?i)\bDAN\b[^\n]{0,80}?(?:do\s+anything|no\s+rules?|unrestricted|jailbroken|without\s+(?:rules?|limits?|restrictions?))",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)(?:do\s+anything|no\s+rules?|unrestricted|jailbroken|without\s+(?:rules?|limits?|restrictions?))[^\n]{0,80}?\bDAN\b",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:DAN|STAN|DUDE|jailbroken|unrestricted|developer\s+mode)\b",
        "persona_swap",
        "high",
    ),
    (
        r"(?i)\bwith\s+no\s+(?:rules?|restrictions?|limits?|guidelines?|filters?)\b",
        "jailbreak_persona",
        "medium",
    ),
    (
        r"(?i)\b(?:sudo|developer|god|admin)\s+mode\s+(?:on|enabled?|activated?|access|now)\b",
        "jailbreak_persona",
        "high",
    ),
    (
        r"(?i)\b(?:enable|activate|enter|switch\s+to)\s+(?:sudo|developer|god|admin)\s+mode\b",
        "jailbreak_persona",
        "high",
    ),

    # System-prompt exfiltration
    (
        r"(?i)\b(?:reveal|show|print|repeat|output|leak|expose)\s+(?:your\s+|the\s+)?(?:system\s+|hidden\s+|initial\s+|original\s+)?(?:prompt|instructions?)",
        "exfil_system_prompt",
        "high",
    ),
    (
        r"(?i)\b(?:what|tell\s+me)\s+(?:are|were|is)\s+your\s+(?:original\s+|system\s+|initial\s+)?(?:instructions?|prompt|rules)",
        "exfil_system_prompt",
        "high",
    ),

    # Indirect / RAG injection
    (
        r"(?i)when\s+(?:the\s+)?AI\s+(?:reads?|processes?|sees?)\s+this\S*(?:\s+\S+){0,18}\s+(?:it\s+(?:must|should|will)|do|execute|run)",
        "indirect_injection",
        "high",
    ),
    (
        r"(?i)if\s+you\s+(?:are|'re)\s+(?:an?\s+)?(?:AI|LLM|language\s+model)\S*(?:\s+\S+){0,12}\s+(?:follow|obey|execute|perform)",
        "indirect_injection",
        "medium",
    ),

    # Safety bypass vocabulary
    (
        r"(?i)(jailbreak|bypass|circumvent|neutralize|disable)\s+(the\s+)?(safety|filter|guard|restrict|censor|moderat)",
        "safety_bypass",
        "high",
    ),
    (
        r"(?i)(unlock|remove|disable)\s+(your\s+)?(restrictions?|safety\s+filters?|content\s+(policy|filter))",
        "safety_bypass",
        "high",
    ),

    # Many-shot / separator abuse
    (
        r"(?i)(---+|===+|___+)\s*(new\s+instruction|system\s+prompt|ignore\s+above)",
        "separator_abuse",
        "medium",
    ),
]

_COMPILED: list[tuple[re.Pattern, str, str]] = [
    (re.compile(pat), label, severity)
    for pat, label, severity in _RAW_PATTERNS
]


@dataclass
class InjectionMatch:
    """A single matched injection pattern from an :class:`InjectionDetector` scan.

    Attributes
    ----------
    pattern_label:
        Human-readable category of the match (e.g. ``instruction_override``,
        ``jailbreak_persona``, ``token_injection``).
    severity:
        Severity level: ``"high"``, ``"medium"``, or ``"low"``.
    matched_text:
        The substring that triggered the pattern (capped at 120 chars).
    """
    pattern_label: str
    severity: str
    matched_text: str


@dataclass
class InjectionResult:
    """Result of scanning text for prompt injection or jailbreak patterns.

    Attributes
    ----------
    detected:
        True if at least one injection pattern was matched.
    matches:
        List of all :class:`InjectionMatch` objects that fired, ordered by
        detection. Check the ``severity`` property for the highest-severity match.
    """
    detected: bool
    matches: List[InjectionMatch] = field(default_factory=list)

    @property
    def severity(self) -> Optional[str]:
        """Highest severity among all matches, or None if clean."""
        if not self.matches:
            return None
        order = {"high": 2, "medium": 1, "low": 0}
        return max(self.matches, key=lambda m: order.get(m.severity, 0)).severity

    @property
    def matched_pattern(self) -> Optional[str]:
        """Label of the highest-severity match, or None."""
        if not self.matches:
            return None
        order = {"high": 2, "medium": 1, "low": 0}
        return max(self.matches, key=lambda m: order.get(m.severity, 0)).pattern_label

    def __bool__(self) -> bool:
        return self.detected


class InjectionDetector:
    """Regex-based prompt injection and jailbreak detector.

    Parameters
    ----------
    extra_patterns : list[tuple[str, str, str]], optional
        Additional ``(regex_pattern, label, severity)`` tuples appended to the
        built-in library.  Useful for domain-specific injection patterns.
    min_severity : str
        Minimum severity level to flag.  ``"high"`` means only high-severity
        matches are reported; ``"low"`` reports everything.  Default: ``"low"``.
    """

    def __init__(
        self,
        extra_patterns: list[tuple[str, str, str]] | None = None,
        min_severity: str = "low",
    ) -> None:
        self._patterns = list(_COMPILED)
        if extra_patterns:
            self._patterns.extend(
                (re.compile(p), lbl, sev)
                for p, lbl, sev in extra_patterns
            )
        _order = {"high": 2, "medium": 1, "low": 0}
        self._min_level = _order.get(min_severity, 0)

    def scan(self, text: str) -> InjectionResult:
        """Scan *text* for injection patterns.

        Returns an :class:`InjectionResult`.  Check ``result.detected`` or
        ``bool(result)`` for a quick yes/no answer.

        Parameters
        ----------
        text:
            The text to scan (user input, retrieved document, tool output, etc.)
        """
        _order = {"high": 2, "medium": 1, "low": 0}
        matches: list[InjectionMatch] = []

        for pattern, label, severity in self._patterns:
            if _order.get(severity, 0) < self._min_level:
                continue
            m = pattern.search(text)
            if m:
                matches.append(
                    InjectionMatch(
                        pattern_label=label,
                        severity=severity,
                        matched_text=m.group(0)[:120],  # cap length for logs
                    )
                )

        return InjectionResult(detected=bool(matches), matches=matches)

    def scan_many(self, texts: list[str]) -> list[InjectionResult]:
        """Scan multiple texts.  Returns one result per input."""
        return [self.scan(t) for t in texts]
