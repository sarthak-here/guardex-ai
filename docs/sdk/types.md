# SDK Reference: Types & Constants

Type definitions and constants exported by the GuardEx SDK.

---

## Import

```python
from guardex import (
    # Result types
    ScreenResult,
    ClassifyResult,
    PIIResult,
    PIIEntity,
    ScopeResult,
    SafetyRouteOutcome,
    GateTrace,
    GroundingResult,
    SentenceGroundingResult,
    # Type aliases
    Gate,
    Action,
    # Constants
    ALL_CATEGORIES,
    DEFAULT_BLOCKED,
    DEFAULT_PII_ENTITIES,
    CATEGORY_DESCRIPTIONS,
)
```

---

## Result Types

### ScreenResult

The primary result from `guard.screen()`. Contains the full screening decision.

```python
@dataclass(frozen=True)
class ScreenResult:
    gate: str                          # Gate where screening happened
    action: Action                     # "pass", "block", or "mask" (never "flag")
    classify: ClassifyResult           # Safety classification result
    pii: PIIResult                     # PII detection result
    text: str                          # Processed text (masked if PII found)
    scope: Optional[ScopeResult] = None            # Topic scope result (if scope configured)
    safety_route: Optional[SafetyRouteOutcome] = None  # User-defined safety-route hit
    latency_ms: float = 0.0            # Round-trip latency
    request_id: Optional[str] = None   # API request ID for debugging
    gates_run: tuple[str, ...] = ()    # Gates that evaluated this call
    diagnostics: tuple[GateTrace, ...] = ()  # Per-gate timing and skip reasons
    degraded: bool = False             # True when returned via a fail-open path
```

Gate ordering in the default cascade: `injection` → `input_validation` → `keyword` → `classify` → `pii` → `scope` → `safety_route`. When several gates would block, action precedence is scope > safety_route > classify > pii.

**Convenience properties:**

| Property | Type | Description |
|----------|------|-------------|
| `safe` | `bool` | `True` if `action` is `"pass"` or `"mask"`, content is in scope, and no safety route blocked |
| `blocked` | `bool` | `True` if `action` is `"block"`, content is out of scope, or a safety route blocked |
| `in_scope` | `bool` | `True` if no topic scope configured, or query is within scope |

**Example:**

```python
result = guard.screen("My email is test@example.com", gate="input")

result.gate          # "input"
result.action        # "mask"
result.safe          # True (content is safe, PII was masked)
result.blocked       # False
result.text          # "My email is [EMAIL]"
result.latency_ms    # 42.5
result.request_id    # "req_abc123"
result.classify      # ClassifyResult(safe=True, ...)
result.pii           # PIIResult(has_pii=True, ...)
```

---

### ClassifyResult

Safety classification result.

```python
@dataclass(frozen=True)
class ClassifyResult:
    safe: bool                             # True if content is safe
    category: Optional[str] = None         # Primary unsafe category (e.g., "S9")
    categories: list[str] = field(default_factory=list)  # All detected categories
    confidence: float = 1.0                # Classification confidence
    description: Optional[str] = None      # Human-readable category label
```

**Example:**

```python
result = guard.classify("How to make explosives?", gate="input")

result.safe          # False
result.category      # "S9"
result.categories    # ["S9"]
result.confidence    # 0.98
result.description   # "Indiscriminate Weapons"
```

---

### PIIResult

PII detection result.

```python
@dataclass(frozen=True)
class PIIResult:
    has_pii: bool                          # Whether PII was detected
    entities: list[PIIEntity] = field(default_factory=list)  # Detected entities
    masked_text: Optional[str] = None      # Text with PII replaced (if masked)
```

**Example:**

```python
result = guard.pii_scan("Email: alice@example.com, SSN: 123-45-6789")

result.has_pii      # True
result.masked_text   # None (pii_scan only detects, use pii_mask() or screen() for masking)
result.entities      # [PIIEntity(text="alice@example.com", label="email", ...), ...]
```

---

### PIIEntity

A single PII detection.

```python
@dataclass(frozen=True)
class PIIEntity:
    text: str       # Detected text (e.g., "alice@example.com")
    label: str      # Entity type (e.g., "email")
    score: float    # Confidence (0.0 - 1.0)
    start: int      # Character offset start
    end: int        # Character offset end
```

**Example:**

```python
for entity in result.entities:
    print(f"{entity.label}: '{entity.text}' "
          f"(confidence={entity.score:.2f}, span={entity.start}:{entity.end})")
    # email: 'alice@example.com' (confidence=0.96, span=7:26)
```

---

### ScopeResult

Result of topic scope checking. Only present when `TopicScope` is configured on the policy.

```python
@dataclass(frozen=True)
class ScopeResult:
    allowed: bool = True                    # Whether the query is within scope
    distance: float = 0.0                   # Cosine similarity distance
    matched_topic: Optional[str] = None     # Which topic anchor matched
    confidence: float = 1.0                 # Confidence score
    reason: Optional[str] = None            # Explanation if out of scope
```

**Example:**

```python
result = guard.screen("What's my account balance?", gate="input")

if result.scope:
    print(result.scope.allowed)        # True
    print(result.scope.matched_topic)  # "retail banking"
    print(result.scope.confidence)     # 0.92

print(result.in_scope)  # True (convenience property)
```

---

### SafetyRouteOutcome

A single user-defined safety-route hit attached to a `ScreenResult`. Present only when `safety_routes` are configured on the policy and one matches.

```python
@dataclass(frozen=True, slots=True)
class SafetyRouteOutcome:
    matched: bool = False                # Whether a route matched
    route_name: Optional[str] = None     # Name of the matched route
    action: Optional[str] = None         # "block", "flag", or None
    similarity: float = 0.0              # Match similarity score
    description: str = ""                # Route description
```

---

### GateTrace

Per-gate diagnostic record captured during a `screen()` call, carried in `ScreenResult.diagnostics`.

```python
@dataclass(frozen=True, slots=True)
class GateTrace:
    gate: str                            # injection, input_validation, keyword,
                                         # classify, pii, scope, safety_route
    ran: bool                            # False when the gate was skipped
    skipped_reason: Optional[str] = None
    duration_ms: float = 0.0
    blocked: bool = False
    note: Optional[str] = None
```

---

### SentenceGroundingResult

Per-sentence grounding verdict from the NLI/embedding engine.

```python
@dataclass(frozen=True, slots=True)
class SentenceGroundingResult:
    sentence: str                          # The claim text
    grounded: bool                         # Is this claim supported?
    score: float                           # Entailment confidence (0.0-1.0)
    matched_chunk: Optional[str] = None    # Source chunk compared
    verdict: str = "grounded"              # "grounded" | "contradicted" | "ungrounded" | "uncertain"
    contradiction: float = 0.0             # Contradiction confidence
    neutral: float = 0.0                   # Neutral confidence
```

### GroundingResult

Aggregate result from `guard.check_grounding()`.

```python
@dataclass(frozen=True, slots=True)
class GroundingResult:
    grounded: bool                         # Overall verdict
    faithfulness_score: float = 1.0        # Fraction of claims grounded (0.0-1.0)
    has_contradiction: bool = False        # Any claim contradicts a source
    sentence_count: int = 0                # Total claims checked
    grounded_count: int = 0                # Claims supported by sources
    contradicted_count: int = 0            # Claims contradicting sources
    ungrounded_count: int = 0              # Claims with no source support
    uncertain_count: int = 0               # Claims with ambiguous evidence
    details: list[SentenceGroundingResult] = field(default_factory=list)  # Per-claim results
    mode: str = "accuracy"                 # "speed" or "accuracy"
    latency_ms: float = 0.0
    request_id: Optional[str] = None
```

**Computed properties:**

| Property | Type | Description |
|----------|------|-------------|
| `hallucinated` | `bool` | `not self.grounded` - True if response contains hallucinations |
| `hallucinated_sentences` | `list[SentenceGroundingResult]` | Only the ungrounded sentences |

**Example:**

```python
result = guard.check_grounding(llm_response, sources=chunks)

result.grounded            # True
result.hallucinated        # False (computed property)
result.faithfulness_score  # 0.85
result.has_contradiction   # False
result.contradicted_count  # 0
result.uncertain_count     # 1

for s in result.hallucinated_sentences:
    print(f"{s.sentence} - {s.verdict} (score={s.score:.2f})")
```

---

## Type Aliases

### Gate

All valid gate positions in the LLM pipeline.

```python
Gate = Literal[
    "input",              # User prompt
    "prompt",             # Assembled prompt (system + user)
    "stream",             # Streaming chunks
    "output",             # Full LLM response
    "tool_input",         # Tool/function call arguments
    "tool_output",        # Tool return value
    "retrieval_query",    # Vector store query
    "retrieval_result",   # Documents from retrieval
]
```

### Action

Possible screening outcomes.

```python
Action = Literal["pass", "block", "mask", "flag"]
```

| Action | Meaning |
|--------|---------|
| `"pass"` | Content is safe, no PII detected |
| `"block"` | Content is unsafe and was blocked |
| `"mask"` | PII was detected and masked with `[LABEL]` placeholders |
| `"flag"` | Reserved for future use - not currently returned by any code path |

---

## Constants

### ALL_CATEGORIES

All 14 LlamaGuard safety category codes.

```python
ALL_CATEGORIES: list[str] = [
    "S1", "S2", "S3", "S4", "S5", "S6", "S7",
    "S8", "S9", "S10", "S11", "S12", "S13", "S14",
]
```

### DEFAULT_BLOCKED

The 5 categories blocked by default.

```python
DEFAULT_BLOCKED: list[str] = ["S1", "S3", "S4", "S9", "S11"]
```

### DEFAULT_PII_ENTITIES

All 31 PII entity types detected by default across 5 categories.

```python
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
```

### CATEGORY_DESCRIPTIONS

Human-readable names for all 14 safety categories.

```python
CATEGORY_DESCRIPTIONS: dict[str, str] = {
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
```

`CATEGORY_DESCRIPTIONS` also contains `"S0": "Input Validation"`, the synthetic
code emitted when input fails length/repetition/empty validation. `S0` is
excluded from `ALL_CATEGORIES` and is always blocked regardless of policy.

---

## Gate Mapping

All 8 gate names are passed to the server verbatim. The server accepts all 8 values and maps them internally to a direction (input vs. output) for classification:

| Gate (client) | Stage (server) | Direction |
|--------------|----------------|-----------|
| `input` | `input` | Input |
| `prompt` | `prompt` | Input |
| `stream` | `stream` | Output |
| `output` | `output` | Output |
| `tool_input` | `tool_input` | Input |
| `tool_output` | `tool_output` | Output |
| `retrieval_query` | `retrieval_query` | Input |
| `retrieval_result` | `retrieval_result` | Output |

This mapping is handled automatically - you only need to think in terms of gates.
