# SDK Reference: GuardExPolicy

`guardex.GuardExPolicy` - Configuration dataclass for all GuardEx SDK behavior.

---

## Import

```python
from guardex import GuardExPolicy
```

---

## Constructor

```python
@dataclass
class GuardExPolicy:
    # Server connection
    api_key: str = ""                           # GUARDEX_API_KEY env var
    base_url: str = ""                          # GUARDEX_BASE_URL env var; empty = local mode
    timeout: int = 30
    fail_open: bool = False

    # Content moderation
    block_on_unsafe_input: bool = True
    block_on_unsafe_output: bool = True
    blocked_categories: list[str] = field(default_factory=lambda: ["S1", "S3", "S4", "S9", "S11"])

    # PII detection
    pii_enabled: bool = True
    pii_entities: list[str] = DEFAULT_PII_ENTITIES
    pii_action: Literal["mask", "block"] = "mask"
    pii_threshold: float = 0.85
    pii_allow_list: list[str] = DEFAULT_PII_ALLOW_LIST   # 21 conversational tokens
    pii_deny_list: list[str] = field(default_factory=list)

    # Topic scope restriction
    topic_scope: TopicScope | None = None

    # Server processing
    cascade_mode: Literal["safety", "speed"] = "safety"

    # False-positive tuning
    classify_min_confidence: float = 0.0
```

See [Configuration Guide](../guides/configuration.md) for detailed parameter descriptions and usage examples.

---

## Field Reference

### Server Connection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | `str` | `""` (reads `GUARDEX_BASE_URL`) | GuardEx server URL. Empty selects local in-process mode; any non-empty value selects server mode. |
| `api_key` | `str` | `""` (reads `GUARDEX_API_KEY`) | API key for a hosted server. Setting it puts `Guard` in server mode. |
| `timeout` | `int` | `30` | HTTP request timeout in seconds. |
| `fail_open` | `bool` | `False` | When `True`, treat server errors (network, 5xx) as SAFE. When `False`, raise `GuardExAPIError` on failure. Note: 401/403/422 errors always raise regardless. |

### Content Moderation

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_on_unsafe_input` | `bool` | `True` | Gate the safety-classifier verdict for input gates (`input`, `prompt`, `tool_input`, `retrieval_query`). When `False`, `screen()` still reports the unsafe verdict but enforcement methods stop raising on it. Injection, topic scope, safety routes, and `pii_action="block"` are independent and always enforce. |
| `block_on_unsafe_output` | `bool` | `True` | Same rule for output gates (`output`, `tool_output`, `retrieval_result`). |
| `blocked_categories` | `list[str]` | `["S1", "S3", "S4", "S9", "S11"]` | LlamaGuard safety category codes that trigger a block (default: violent crimes, sex-related crimes, child sexual exploitation, indiscriminate weapons, suicide & self-harm). See [Semantic Categories](#semantic-category-names). |

### PII Detection

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pii_enabled` | `bool` | `True` | Enable PII detection. |
| `pii_entities` | `list[str]` | `DEFAULT_PII_ENTITIES` | Entity types to detect. See [PII Entity Types](#pii-entity-types). |
| `pii_action` | `"mask" \| "block"` | `"mask"` | When PII is found: `"mask"` replaces with placeholders, `"block"` blocks the request. `Guard.screen()` returns a blocked `ScreenResult` (it never raises `PIIViolation`); `GuardExClient` and the LangChain wrappers raise `PIIViolation`. |
| `pii_threshold` | `float` | `0.85` | Confidence threshold (0.0–1.0). Detections below this are ignored. Real PII scores >=0.95; the 0.6–0.8 band is where GLiNER false positives land, so keep the default at or above 0.85. |
| `pii_allow_list` | `list[str]` | 21 conversational tokens | Strings suppressed from PII findings (`hi`, `hello`, `ok`, ...) that GLiNER may otherwise mis-tag in the 0.6–0.8 band. |
| `pii_deny_list` | `list[str]` | `[]` | Exact strings always tagged as PII (score 1.0). Use for known sensitive identifiers. |
| `pii_custom_regex` | `dict[str, str]` | `{}` | Extra `label -> regex` (case-insensitive) added to detection. |
| `pii_custom_context_keywords` | `dict[str, list[str]]` | `{}` | Extra `label -> keywords` that boost confidence when a keyword appears near a candidate. |

### Topic Scope (Optional)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `topic_scope` | `TopicScope \| None` | `None` | Optional scope restriction. Queries outside defined topics are blocked. See [TopicScope](#topicscope-class-reference). |

### Server Processing
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `cascade_mode` | `"safety" \| "speed"` | `"safety"` | Server processing mode. See [Server Processing](#server-processing). |

### False-Positive Tuning
| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `classify_min_confidence` | `float` | `0.0` | Minimum confidence required to trust a classification. If the server returns `confidence < classify_min_confidence`, the SDK overrides to SAFE. Default `0.0` means trust all server results. Set to e.g. `0.7` to auto-pass low-confidence unsafe classifications. See [False-Positive Tuning](#false-positive-tuning). |

---

## Server Processing

### cascade_mode: "safety" vs "speed"

The `cascade_mode` field controls how the GuardEx server processes your request:

**`"safety"` (default)**
- All classification checks run fully.
- Content Safety and PII detection both complete.
- Maximum accuracy; slightly higher latency.
- Recommended for high-stakes applications.

```python
policy = GuardExPolicy(cascade_mode="safety")
# Server runs all checks before returning
```

**`"speed"`**
- Server enables fast-path evaluation.
- Unsafe content detected at input is short-circuited early.
- Lower latency for blocked requests.
- Recommended for real-time chat with high throughput.

```python
policy = GuardExPolicy(cascade_mode="speed")
# Server skips remaining checks if input is unsafe
```

**Note:** `"speed"` skips the LlamaGuard escalation layer, so it can miss content the full cascade would catch. With the binary local classifier, per-category filtering is unavailable in speed mode.

---

## False-Positive Tuning

### classify_min_confidence: Confidence threshold override

The `classify_min_confidence` field lets you filter out low-confidence unsafe classifications. This is useful when the classifier is uncertain and you want to reduce false positives:

```python
# Default: trust all server results
policy = GuardExPolicy(classify_min_confidence=0.0)
result = guard.screen("ambiguous text", gate="input")
# If server returns unsafe with confidence=0.55, SDK respects it

# Strict mode: only block high-confidence unsafe
policy = GuardExPolicy(classify_min_confidence=0.8)
result = guard.screen("ambiguous text", gate="input")
# If server returns unsafe with confidence=0.55, SDK overrides to SAFE
```

**Workflow:**
1. Monitor audit logs or user feedback for false positives.
2. If low-confidence blocks appear, raise `classify_min_confidence` incrementally (e.g., 0.6 → 0.7 → 0.8).
3. Trade off: higher threshold → fewer false positives, but some unsafe content may pass.

**Default value:** `0.0` means "trust the server." Set to `0.5`–`0.9` depending on tolerance.

---

## Class Methods

### from_yaml()

Load policy from a YAML file.

```python
GuardExPolicy.from_yaml(path: str) -> GuardExPolicy
```

Requires `PyYAML` (`pip install pyyaml`).

```python
policy = GuardExPolicy.from_yaml("guardex_policy.yaml")
guard = Guard(policy=policy)
```

YAML format:

```yaml
base_url: http://localhost:8001
timeout: 30

# Content moderation
blocked_categories: [S1, S3, S4, S9, S11]

# PII detection
pii_enabled: true
pii_entities: [email, phone_number, ssn]
pii_action: mask
pii_threshold: 0.85

# Topic scope
topic_scope:
  topics: [retail banking, credit cards]
  scope_width: moderate

cascade_mode: safety
classify_min_confidence: 0.0
```

---

## Constants

### PII Entity Types

Default PII entities detected when `pii_entities` is not overridden (31 types across 5 categories):

```python
DEFAULT_PII_ENTITIES = [
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

Use custom entity lists to detect a subset:

```python
policy = GuardExPolicy(pii_entities=["email", "phone_number", "ssn"])
# Only these three entity types are detected
```

### Safety Categories

GuardEx uses LlamaGuard's 14 safety categories:

```python
ALL_CATEGORIES = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14"]
```

---

## Semantic Category Names

### Overview

Use **semantic names** in code instead of opaque S-codes. Both forms are accepted everywhere and automatically converted:

```python
# These are equivalent:
policy = GuardExPolicy(blocked_categories=["S11"])
policy = GuardExPolicy(blocked_categories=["self_harm"])

result.classify.category  # Always returns "S11"
```

### CATEGORY_ALIASES

Map semantic names to S-codes:

```python
from guardex import CATEGORY_ALIASES

CATEGORY_ALIASES = {
    "violent_crimes":            "S1",
    "non_violent_crimes":        "S2",
    "sex_related_crimes":        "S3",
    "sex_crimes":                "S3",
    "child_sexual_exploitation": "S4",
    "child_exploitation":        "S4",
    "defamation":                "S5",
    "specialized_advice":        "S6",
    "privacy":                   "S7",
    "intellectual_property":     "S8",
    "indiscriminate_weapons":    "S9",
    "weapons":                   "S9",
    "hate":                      "S10",
    "suicide_self_harm":         "S11",
    "self_harm":                 "S11",
    "sexual_content":            "S12",
    "elections":                 "S13",
    "code_interpreter_abuse":    "S14",
}
```

Several codes have two accepted aliases (e.g. `weapons` and `indiscriminate_weapons` both resolve to `S9`).

### CATEGORY_CODE_TO_NAME

Reverse map (S-code → semantic name):

```python
from guardex import CATEGORY_CODE_TO_NAME

CATEGORY_CODE_TO_NAME = {
    "S1": "violent_crimes",
    "S2": "non_violent_crimes",
    # ... etc
}
```

For codes with two aliases, the reverse map holds the shorter form:
`S3` → `sex_crimes`, `S4` → `child_exploitation`, `S9` → `weapons`,
`S11` → `self_harm`.

### resolve_category()

Convert a semantic name or S-code to its canonical S-code:

```python
from guardex import resolve_category

resolve_category("self_harm")     # → "S11"
resolve_category("S11")           # → "S11"
resolve_category("Self-Harm")     # → "S11" (case-insensitive)
resolve_category("weapons")       # → "S9"
```

Use this when accepting user input:

```python
user_category = request.args.get("block_category")
canonical = resolve_category(user_category)  # Always safe
policy = GuardExPolicy(blocked_categories=[canonical])
```

### resolve_categories()

Resolve a list of names/codes:

```python
from guardex import resolve_categories

resolve_categories(["self_harm", "S9", "weapons"])
# → ["S11", "S9", "S9"]
```

### CATEGORY_DESCRIPTIONS

Human-readable descriptions of all categories:

```python
from guardex import CATEGORY_DESCRIPTIONS

CATEGORY_DESCRIPTIONS = {
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

# Use to display decisions to users
category_name = CATEGORY_DESCRIPTIONS.get(result.classify.category, "Unknown")
```

---

## TopicScope Class Reference

Define allowed topics for your chatbot using semantic anchors and optional examples:

```python
from guardex import TopicScope, GuardExPolicy

scope = TopicScope(
    topics=["retail banking", "credit cards", "loan products"],
    examples=["What's my account balance?", "How do I apply for a mortgage?"],
    scope_width="moderate",
)
policy = GuardExPolicy(topic_scope=scope)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `topics` | `list[str]` | `[]` | Anchor descriptions of allowed topics, matched by semantic similarity. |
| `utterances` | `dict[str, list[str]] \| None` | `None` | Optional per-topic example phrases. More precise than `topics` alone. |
| `examples` | `list[str] \| None` | `None` | Optional in-scope example queries. Improves accuracy by grounding the classifier. |
| `scope_width` | `str` | `"moderate"` | Enforcement strictness: `"narrow"` (only clearly on-topic), `"moderate"` (allows related), `"broad"` (only clearly off-topic blocked), `"fitted"` (threshold set by `fit()`). |
| `threshold` | `float \| None` | `None` | Manual cosine similarity threshold (0.0–1.0). Overrides `scope_width` if set. |
| `alpha` | `float` | `0.0` | Hybrid dense+BM25 weight (0.0 = dense only). Only effective when `utterances` are provided. |
| `encoder_type` | `str \| None` | `None` | Encoder to embed with: `"sentence-transformer"` (default), `"openai"`, `"fastembed"`, `"ollama"`. |
| `encoder_config` | `dict \| None` | `None` | Extra kwargs passed to the encoder constructor (e.g. model, api_key). |

### Example: Banking Bot

```python
scope = TopicScope(
    topics=[
        "retail banking operations",
        "credit card management",
        "loan and mortgage products",
        "account security",
    ],
    examples=[
        "What is my account balance?",
        "How do I transfer money between accounts?",
        "How do I apply for a mortgage?",
        "What are your credit card interest rates?",
    ],
    scope_width="narrow",  # Strict: only banking queries
)

policy = GuardExPolicy(topic_scope=scope)
guard = Guard(policy=policy)

# This passes (on-topic)
result = guard.screen("What's my account balance?", gate="input")
assert result.in_scope

# This is blocked (off-topic)
result = guard.screen("Tell me a joke", gate="input")
assert not result.in_scope
```

---

# SDK Reference: EffectiveConfig

`guardex.EffectiveConfig` - Typed representation of the merged dashboard + code configuration.

## Import

```python
from guardex import EffectiveConfig
```

## Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `pii` | `PIIMergedConfig` | Merged PII settings |
| `content` | `ContentMergedConfig` | Merged content moderation settings |
| `sources` | `dict` | Maps each field to its source: `"dashboard"`, `"code"`, or `"both"` |
| `conflicts` | `list[str]` | Warning messages about policy conflicts |
| `last_code_config_seen_at` | `str \| None` | ISO timestamp of last code config snapshot |
| `last_dashboard_updated_at` | `str \| None` | ISO timestamp of last dashboard policy update |

### PIIMergedConfig

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | PII detection enabled |
| `entities` | `list[str]` | Entity types to detect |
| `action` | `str` | `"mask"` or `"block"` |
| `threshold` | `float` | Confidence threshold |

### ContentMergedConfig

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | `bool` | Content moderation enabled |
| `blocked_categories` | `list[str]` | Blocked category codes |
| `check_input` | `bool` | Screen input |
| `check_output` | `bool` | Screen output |

## Class Methods

### from_api_response()

Parse from the `GET /v1/config/effective` API response.

```python
EffectiveConfig.from_api_response(data: dict) -> EffectiveConfig
```

## Display

```python
from guardex import GuardExClient

with GuardExClient() as client:
    config = client.get_effective_config()
    print(config)
```

Output:

```
[GuardEx] Effective config
PII:      ON | action: mask | entities: 12
  email                    (both)
  phone_number             (dashboard)
  ...
Content:  ON | blocked: 5 categories
  S1   Violent Crimes          (both)
  S3   Sex-Related Crimes      (dashboard)
  ...

WARNINGS:
  ! Code tried to remove 'S3' but dashboard requires it
```

---

# SDK Reference: Exceptions

## GuardExViolation

```python
from guardex import GuardExViolation
```

Raised when content is classified as unsafe.

| Attribute | Type | Description |
|-----------|------|-------------|
| `stage` | `str` | Gate where the violation occurred (e.g., `"input"`, `"tool_input"`) |
| `category` | `str \| None` | Safety category code (e.g., `"S9"`) |
| `description` | `str \| None` | Human-readable category name (e.g., `"Indiscriminate Weapons"`) |
| `raw_response` | `str` | Sanitized server message |

## PIIViolation

```python
from guardex import PIIViolation
```

Raised when PII is detected and `pii_action='block'`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `stage` | `str` | Gate where PII was detected |
| `entities_found` | `list[dict]` | Detected entities with `label`, `score`, `start`, `end` |

## GuardExAPIError

```python
from guardex import GuardExAPIError
```

Raised on HTTP errors from the GuardEx API.

| Attribute | Type | Description |
|-----------|------|-------------|
| `status_code` | `int` | HTTP status code |
| `error_type` | `str` | Error type from API |
| `message` | `str` | Human-readable message |
| `code` | `str` | Machine-readable error code |

