# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 GuardEx
"""Core types for GuardEx - zero external dependencies.

These types use stdlib dataclasses only. No pydantic, no langchain,
no framework-specific imports. This is the foundation everything
else builds on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Optional, cast


# The 8 Gates

Gate = Literal[
    "input",              # G1: Raw user input
    "prompt",             # G2: Assembled prompt (system + user + context)
    "stream",             # G3: Streaming chunks (handled by StreamGuard)
    "output",             # G4: Full LLM response
    "tool_input",         # G5: Tool/function call arguments
    "tool_output",        # G6: Tool/function return value
    "retrieval_query",    # G7: Query sent to vector store / retriever
    "retrieval_result",   # G8: Documents returned from retrieval
]

Action = Literal["pass", "block", "mask", "flag"]

# Output gate for a given input gate (used by Guard.wrap)
_OUTPUT_GATE: dict[str, str] = {
    "input": "output",
    "tool_input": "tool_output",
    "retrieval_query": "retrieval_result",
    "prompt": "output",
}


def gate_to_stage(gate: str) -> str:
    """Map a Gate to the server's stage parameter.

    Currently an identity (every gate name is also a valid stage name).
    Kept as a public function so server-side stage renames can be handled
    here without touching every call site.
    """
    return gate


def output_gate_for(gate: str) -> "Gate":
    """Return the corresponding output gate for a given input gate."""
    return cast("Gate", _OUTPUT_GATE.get(gate, "output"))


# Result Types

@dataclass(frozen=True, slots=True)
class PIIEntity:
    """A single PII detection."""
    text: str
    label: str
    score: float
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ClassifyResult:
    """Safety classification result."""
    safe: bool
    category: Optional[str] = None
    categories: list[str] = field(default_factory=list)
    confidence: float = 1.0
    description: Optional[str] = None


@dataclass(frozen=True, slots=True)
class PIIResult:
    """PII detection/masking result."""
    has_pii: bool
    entities: list[PIIEntity] = field(default_factory=list)
    masked_text: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ScopeResult:
    """Result of topic scope checking."""
    allowed: bool = True
    distance: float = 0.0
    matched_topic: Optional[str] = None
    confidence: float = 1.0
    reason: Optional[str] = None


@dataclass(frozen=True, slots=True)
class SafetyRouteOutcome:
    """A single user-defined safety-route hit attached to a ScreenResult.

    Mirrors :class:`guardex.safety_route.SafetyRouteResult` but without
    pulling numpy into ``_types``.
    """
    matched: bool = False
    route_name: Optional[str] = None
    action: Optional[str] = None         # "block" | "flag" | None
    similarity: float = 0.0
    description: str = ""


@dataclass(frozen=True, slots=True)
class GateTrace:
    """Per-gate diagnostic record captured during a single screen() call.

    ``gate`` names cover both pre-flight checks and pipeline stages:
    ``injection``, ``input_validation``, ``keyword``, ``classify``, ``pii``,
    ``scope``, ``safety_route``. ``ran`` distinguishes a gate that evaluated
    from one that was skipped (provider missing, disabled by policy, or
    short-circuited by an earlier block).
    """
    gate: str
    ran: bool
    skipped_reason: Optional[str] = None
    duration_ms: float = 0.0
    blocked: bool = False
    note: Optional[str] = None


@dataclass(frozen=True, slots=True)
class SentenceGroundingResult:
    """Grounding result for a single sentence/claim."""
    sentence: str
    grounded: bool
    score: float
    matched_chunk: Optional[str] = None
    verdict: str = "grounded"
    contradiction: float = 0.0
    neutral: float = 0.0


@dataclass(frozen=True, slots=True)
class GroundingResult:
    """Result of grounding/hallucination check."""
    grounded: bool
    faithfulness_score: float = 1.0
    has_contradiction: bool = False
    sentence_count: int = 0
    grounded_count: int = 0
    contradicted_count: int = 0
    ungrounded_count: int = 0
    uncertain_count: int = 0
    details: list[SentenceGroundingResult] = field(default_factory=list)
    mode: str = "accuracy"
    latency_ms: float = 0.0
    request_id: Optional[str] = None

    @property
    def hallucinated(self) -> bool:
        """True if the response contains hallucinated content."""
        return not self.grounded

    @property
    def hallucinated_sentences(self) -> list[SentenceGroundingResult]:
        """Return only the sentences that are NOT grounded."""
        return [s for s in self.details if not s.grounded]


@dataclass(frozen=True)
class ScreenResult:
    """The atomic unit of a guardrails decision.

    Gate ordering (default cascade):
        ``injection`` → ``input_validation`` → ``keyword`` → ``classify`` →
        ``pii`` → ``scope`` → ``safety_route``.

    Earlier gates can short-circuit later ones. ``gates_run`` lists which
    gates evaluated for this call; ``diagnostics`` carries per-gate timing
    and skip reasons. Action precedence (when several gates would block):
    scope > safety_route > classify > pii.
    """
    gate: str
    action: Action
    classify: ClassifyResult
    pii: PIIResult
    text: str
    scope: Optional[ScopeResult] = None
    safety_route: Optional[SafetyRouteOutcome] = None
    latency_ms: float = 0.0
    request_id: Optional[str] = None
    gates_run: tuple[str, ...] = ()
    diagnostics: tuple[GateTrace, ...] = ()
    degraded: bool = False
    """True when this result came from a fail-open path (screening errored and
    was passed through). The verdict is NOT a real screening decision."""

    @property
    def safe(self) -> bool:
        """True if content was passed or masked (not blocked)."""
        if self.scope and not self.scope.allowed:
            return False
        if self.safety_route and self.safety_route.matched and self.safety_route.action == "block":
            return False
        return self.action in ("pass", "mask")

    @property
    def blocked(self) -> bool:
        """True if content was blocked."""
        if self.scope and not self.scope.allowed:
            return True
        if self.safety_route and self.safety_route.matched and self.safety_route.action == "block":
            return True
        return self.action == "block"

    @property
    def in_scope(self) -> bool:
        """Whether the query was within the defined topic scope."""
        return self.scope is None or self.scope.allowed


# Category Constants

# Canonical MLCommons / LlamaGuard 3 category names.  S0 is the
# GuardEx-specific synthetic category emitted by the input validator
# for malformed input (length, repetition, empty); it has no upstream
# equivalent.  All other codes match the upstream model output exactly.
CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "S0":  "Input Validation",
    "S1":  "Violent Crimes",
    "S2":  "Non-Violent Crimes",
    "S3":  "Sex-Related Crimes",
    "S4":  "Child Sexual Exploitation",
    "S5":  "Defamation",
    "S6":  "Specialized Advice",
    "S7":  "Privacy",
    "S8":  "Intellectual Property",
    "S9":  "Indiscriminate Weapons",
    "S10": "Hate",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections",
    "S14": "Code Interpreter Abuse",
}

# S0 is omitted from ALL_CATEGORIES so user-configurable blocked_categories
# never include the synthetic input-validation code (it is always blocked
# regardless of policy when the input fails validation).
ALL_CATEGORIES: list[str] = [c for c in CATEGORY_DESCRIPTIONS if c != "S0"]

# Block-by-default categories.  These five carry the highest harm and
# lowest false-positive risk in the LlamaGuard 3 taxonomy.  Override via
# ``GuardExPolicy(blocked_categories=[...])`` for a different posture.
DEFAULT_BLOCKED: list[str] = ["S1", "S3", "S4", "S9", "S11"]

DEFAULT_PII_ENTITIES: list[str] = [
    # Personal Info (9)
    "email", "phone_number", "name", "address", "ssn",
    "national_id", "passport_number", "date_of_birth", "driver_license",
    # Credentials & Secrets (6)
    "password", "user_name", "private_key", "jwt_token", "auth_header", "secret",
    # API Keys & Tokens (8)
    "api_key", "aws_key", "github_token", "slack_token",
    "stripe_key", "google_api_key", "openai_key", "twilio_sid",
    # Financial (3)
    "credit_card", "bank_account", "iban",
    # Network & Infrastructure (5)
    "ip_address", "ipv6_address", "mac_address", "hostname", "database_url",
]

# Semantic category name aliases (use these in code; S-codes for server)
# Human-readable names map to LlamaGuard S-codes so callers never need to
# memorise opaque codes.  Both forms are accepted everywhere.
CATEGORY_ALIASES: dict[str, str] = {
    "violent_crimes":          "S1",
    "non_violent_crimes":      "S2",
    "sex_related_crimes":      "S3",
    "sex_crimes":              "S3",
    "child_sexual_exploitation": "S4",
    "child_exploitation":      "S4",
    "defamation":              "S5",
    "specialized_advice":      "S6",
    "privacy":                 "S7",
    "intellectual_property":   "S8",
    "indiscriminate_weapons":  "S9",
    "weapons":                 "S9",
    "hate":                    "S10",
    "suicide_self_harm":       "S11",
    "self_harm":               "S11",
    "sexual_content":          "S12",
    "elections":               "S13",
    "code_interpreter_abuse":  "S14",
}

# Reverse map: S-code → semantic name
CATEGORY_CODE_TO_NAME: dict[str, str] = {v: k for k, v in CATEGORY_ALIASES.items()}


def resolve_category(name_or_code: str) -> str:
    """Resolve a semantic category name or S-code to its canonical S-code.

    Accepts both ``"S11"`` and ``"self_harm"`` - always returns the S-code.

    Examples
    --------
    >>> resolve_category("self_harm")
    'S11'
    >>> resolve_category("S11")
    'S11'
    """
    key = name_or_code.lower().replace("-", "_").replace(" ", "_")
    return CATEGORY_ALIASES.get(key, name_or_code.upper())


def resolve_categories(names_or_codes: list[str]) -> list[str]:
    """Resolve a list of semantic names / S-codes to canonical S-codes."""
    return [resolve_category(c) for c in names_or_codes]
