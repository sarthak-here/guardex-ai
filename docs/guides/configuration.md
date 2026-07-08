# Configuration

GuardEx behavior is controlled through the `GuardExPolicy` dataclass. Every setting has a sensible default, so you only need to configure what you want to change.

!!! tip "Zero-config works out of the box"
    With no configuration at all, `Guard()` blocks the 5 most dangerous categories, masks all 31 PII entity types, and fails closed on errors. Most applications don't need any policy customization.

---

## GuardExPolicy

```python
from guardex import Guard, GuardExPolicy

policy = GuardExPolicy(
    # Server connection (omit for local in-process mode)
    base_url="http://localhost:8001",     # or GUARDEX_BASE_URL env var - self-hosted server URL
    timeout=30,                           # request timeout in seconds
    fail_open=False,                      # raise on errors (True = treat as safe)

    # Content moderation
    blocked_categories=["S1", "S3", "S4", "S9", "S11"],  # which categories to block

    # PII detection
    pii_enabled=True,                     # enable PII detection
    pii_entities=[                        # which entity types to detect
        "email", "phone_number", "user_name", "name", "address",
        "ssn", "credit_card", "date_of_birth", "ip_address",
        "password", "api_key", "bank_account",
    ],
    pii_action="mask",                    # 'mask' or 'block'
    pii_threshold=0.85,                   # confidence threshold (0.0 - 1.0)

    # Server processing
    cascade_mode="safety",                # "safety" (thorough, default) or "speed" (fast path)

    # False-positive tuning
    classify_min_confidence=0.0,          # auto-pass if classification confidence < threshold
)

guard = Guard(policy=policy)
```

---

## Parameter Reference

### Connection

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str` | `""` (reads `GUARDEX_BASE_URL`) | GuardEx server URL. Empty selects local in-process mode (no server needed); any non-empty value selects server mode. |
| `timeout` | `int` | `30` | HTTP request timeout in seconds. |
| `fail_open` | `bool` | `False` | When `True`, treat errors as "safe" (log a warning and continue). When `False`, raise exceptions on errors. **Note:** Validation errors (422) always raise regardless of this setting. |

### Content Moderation

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `blocked_categories` | `list[str]` | `["S1", "S3", "S4", "S9", "S11"]` | LlamaGuard category codes that trigger a block. See [Safety Categories](safety-categories.md) for all 14 codes. Per-category filtering requires LlamaGuard (Ollama) or a multilabel classifier; the default local ONNX gate only distinguishes safe/toxic, so a customized subset has no fine-grained effect in local mode without Ollama. |

### PII Detection

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pii_enabled` | `bool` | `True` | Enable or disable PII detection. |
| `pii_entities` | `list[str]` | All 31 types | Which PII entity types to detect. See [PII Detection](pii-detection.md) for all types. |
| `pii_action` | `str` | `"mask"` | `"mask"`: Replace PII with `[LABEL]` placeholders. `"block"`: Block the request (use `guard.screen()` and check `result.pii.has_pii`). |
| `pii_threshold` | `float` | `0.85` | Confidence threshold for PII detection (0.0 = most sensitive, 1.0 = most strict). |

### Cascade Mode
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cascade_mode` | `str` | `"safety"` | `"safety"`: full cascade (keyword gate + ONNX classifier + LlamaGuard when available, default). `"speed"`: fast path that skips LlamaGuard for clear-cut cases (lower latency). In local mode with no Ollama, only the ONNX classifier runs regardless of this setting. |

### False-Positive Tuning
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `classify_min_confidence` | `float` | `0.0` | If the server returns a classification with `confidence < classify_min_confidence`, the SDK overrides it to safe. Useful for reducing false positives in customer-facing apps. Set to `0.7` or `0.8` to ignore low-confidence detections. |

### Semantic Category Names
Both S-codes and semantic names are accepted everywhere:

```python
# These are equivalent:
policy = GuardExPolicy(blocked_categories=["S11"])
policy = GuardExPolicy(blocked_categories=["self_harm"])
```

See [Safety Categories](safety-categories.md) for the full mapping.

---

## Guard Constructor

`Guard` accepts policy settings directly or via a `GuardExPolicy` object:

```python
from guardex import Guard, GuardExPolicy

# Local mode - runs everything in-process, no server needed
guard = Guard()

# Server mode - connect to a running GuardEx server
guard = Guard(base_url="http://localhost:8001")

# Via policy object
guard = Guard(
    policy=GuardExPolicy(
        blocked_categories=["S1", "S3", "S4", "S9", "S11"],
        pii_action="mask",
        cascade_mode="speed",
        classify_min_confidence=0.7,
    ),
    on_block=lambda r: print(f"Blocked: {r.classify.category}"),
    injection_check=True,  # client-side injection detection (default True)
)
```

---

## Environment Variables

Connection settings can be set via environment variables:

| Variable | Maps to | Default |
|----------|---------|---------|
| `GUARDEX_BASE_URL` | `base_url` | (none - runs in-process) |

Create a `.env` file in your project root (only needed when connecting to a server):

```bash
GUARDEX_BASE_URL=http://localhost:8001
```

---

## Loading from YAML

You can define your policy in a YAML file:

```yaml
# guardex_policy.yaml
blocked_categories:
  - S1
  - S3
  - S4
  - S9
  - self_harm    # semantic names work in YAML too
pii_enabled: true
pii_action: mask
pii_threshold: 0.85
pii_entities:
  - email
  - phone_number
  - ssn
  - credit_card
fail_open: false
timeout: 30

cascade_mode: safety            # "safety" (default) or "speed"
classify_min_confidence: 0.0    # false-positive tuning

# Topic scope
topic_scope:
  topics:
    - retail banking
    - credit cards
  examples:
    - "What's my account balance?"
  scope_width: moderate
```

Load it in your code:

```python
from guardex import GuardExPolicy, Guard

policy = GuardExPolicy.from_yaml("guardex_policy.yaml")
guard = Guard(policy=policy)
```

> **Note:** YAML support requires `PyYAML` (`pip install pyyaml`).

---

## Common Configurations

### Maximum Safety (Block Everything) { #max-safety }

```python
from guardex import Guard, GuardExPolicy, ALL_CATEGORIES

guard = Guard(policy=GuardExPolicy(
    blocked_categories=ALL_CATEGORIES,  # All 14 categories
    pii_action="block",                 # Block on any PII
    pii_threshold=0.5,                  # Lower than 0.85 default - more sensitive
    fail_open=False,                    # Strict error handling
))
```

### Permissive (Mask PII, Never Block)

```python
guard = Guard(policy=GuardExPolicy(
    blocked_categories=[],          # Don't block any safety categories
    pii_action="mask",              # Mask PII but don't block
    fail_open=True,                 # Don't raise on errors
))
```

### PII-Only Mode (No Content Moderation)

```python
guard = Guard(policy=GuardExPolicy(
    blocked_categories=[],
    pii_enabled=True,
    pii_action="mask",
))
```

### Content Moderation Only (No PII)

```python
guard = Guard(policy=GuardExPolicy(
    pii_enabled=False,
    blocked_categories=["S1", "S3", "S4", "S9", "S11"],
))
```

### Custom PII Entities

Detect only specific PII types:

```python
guard = Guard(policy=GuardExPolicy(
    pii_entities=["email", "ssn", "credit_card"],
    pii_action="block",
))
```

### High Sensitivity PII Detection

Lower the threshold to catch more potential PII (may increase false positives):

```python
guard = Guard(policy=GuardExPolicy(
    pii_threshold=0.3,  # Default is 0.85
))
```

### Context-Aware Healthcare
```python
from guardex import Guard, GuardExPolicy, GuardExContext, DeploymentContext, UserContext, Region, Industry

policy = GuardExPolicy(
    pii_action="block",
    cascade_mode="safety",
)
guard = Guard(policy=policy)

ctx = GuardExContext(
    deployment=DeploymentContext.PRODUCTION,
    user=UserContext(region=Region.EU, industry=Industry.HEALTHCARE),
)

# Context auto-adds HIPAA/GDPR PII entities, lowers threshold
result = guard.screen("patient data here", gate="input", context=ctx)
```

### False-Positive Tolerant
For customer-facing apps where false positives are worse than false negatives:

```python
guard = Guard(policy=GuardExPolicy(
    classify_min_confidence=0.8,  # Ignore low-confidence classifications
    pii_threshold=0.9,            # Only flag high-confidence PII
    cascade_mode="speed",         # Faster, slightly less thorough
))
```

### Maximum Thoroughness
```python
guard = Guard(policy=GuardExPolicy(
    cascade_mode="safety",        # Full cascade including LlamaGuard
    fail_open=False,              # Never silently pass on errors
))
```

---

## Topic Scope Restriction

Restrict your chatbot to specific topics. Queries outside the defined scope are blocked.

```python
from guardex import Guard, GuardExPolicy, TopicScope

policy = GuardExPolicy(
    topic_scope=TopicScope(
        topics=["retail banking", "credit cards", "loan products"],
        examples=["What's my account balance?", "How do I apply for a mortgage?"],
        scope_width="moderate",  # "narrow" | "moderate" | "broad"
    ),
)

guard = Guard(policy=policy)

result = guard.screen("What's the weather today?", gate="input")
print(result.in_scope)  # False - off-topic query blocked
print(result.blocked)   # True

result = guard.screen("What's my credit card limit?", gate="input")
print(result.in_scope)  # True - on-topic query allowed
print(result.safe)      # True
```

### TopicScope Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `topics` | `list[str]` | `[]` | Anchor descriptions defining allowed scope |
| `examples` | `list[str] \| None` | `None` | Optional example in-scope queries (improves accuracy) |
| `scope_width` | `str` | `"moderate"` | How strictly to enforce: `"narrow"`, `"moderate"`, or `"broad"` |
| `threshold` | `float \| None` | `None` | Manual cosine similarity threshold override (0.0-1.0) |

### Scope Width Presets

| Width | Behavior |
|-------|----------|
| `narrow` | Only clearly on-topic queries pass |
| `moderate` | Allows related queries (default) |
| `broad` | Only clearly off-topic queries are blocked |

### Loading from YAML

```yaml
# guardex_policy.yaml
topic_scope:
  topics:
    - retail banking
    - credit cards
    - loan products
  examples:
    - "What's my account balance?"
    - "How do I apply for a mortgage?"
  scope_width: moderate
```

---

## Constants

### ALL_CATEGORIES

```python
from guardex import ALL_CATEGORIES

print(ALL_CATEGORIES)
# ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9', 'S10', 'S11', 'S12', 'S13', 'S14']
```

### DEFAULT_BLOCKED

```python
from guardex import DEFAULT_BLOCKED

print(DEFAULT_BLOCKED)
# ['S1', 'S3', 'S4', 'S9', 'S11']
```

### DEFAULT_PII_ENTITIES

```python
from guardex import DEFAULT_PII_ENTITIES

print(DEFAULT_PII_ENTITIES)
# ['email', 'phone_number', 'name', 'address', 'ssn', 'national_id',
#  'passport_number', 'date_of_birth', 'driver_license', 'password',
#  'user_name', 'private_key', 'jwt_token', 'auth_header', 'secret',
#  'api_key', 'aws_key', 'github_token', 'slack_token', 'stripe_key',
#  'google_api_key', 'openai_key', 'twilio_sid', 'credit_card',
#  'bank_account', 'iban', 'ip_address', 'ipv6_address', 'mac_address',
#  'hostname', 'database_url']  # 31 entity types across 5 categories
```

### CATEGORY_DESCRIPTIONS

```python
from guardex import CATEGORY_DESCRIPTIONS

for code, name in CATEGORY_DESCRIPTIONS.items():
    print(f"  {code}: {name}")
# S1: Violent Crimes
# S2: Non-Violent Crimes
# S3: Sex-Related Crimes
# ...
```

---

## Local In-Process Mode: guardex.yaml

When using `pip install guardex-ai[local]`, GuardEx looks for a `guardex.yaml` file in your project root to configure the local ML models.

Copy `guardex.yaml.example` (in the repo root) to `guardex.yaml` and edit as needed:

```yaml
# guardex.yaml - optional configuration for GuardEx in-process mode

# ── Model selection ────────────────────────────────────────────
models:
  # HuggingFace ONNX safety classifier (~100 MB on first use)
  classifier: AtliQ-Technologies/toxicity-fast-onnx

  # GLiNER PII detector model
  pii: nvidia/gliner-pii

  # Sentence-transformers for topic scope + grounding
  embeddings: sentence-transformers/all-MiniLM-L6-v2

  # Optional: Ollama endpoint for LlamaGuard deep-safety layer
  # Requires: ollama pull llama-guard3:1b && ollama serve
  ollama_url: http://localhost:11434
  ollama_model: llama-guard3:1b

# ── Cache ──────────────────────────────────────────────────────
# Directory for downloaded model files (~150 MB on first use)
cache_dir: ~/.cache/guardex

# ── Policy defaults ────────────────────────────────────────────
policy:
  fail_open: false
```

The local engine honors only these keys: `models.classifier`, `models.pii`, `models.embeddings`, `models.ollama_url`, `models.ollama_model`, `policy.fail_open`, and `cache_dir`. Other policy settings belong in `GuardExPolicy` (or a policy YAML loaded via `GuardExPolicy.from_yaml()`).

Environment variables with the `GUARDEX_` prefix take precedence over `guardex.yaml`:

```bash
GUARDEX_CACHE_DIR=/tmp/guardex-models  # Override model cache directory
```

### Using Ollama with local mode

For the deepest safety coverage in local mode, install [Ollama](https://ollama.ai) and pull LlamaGuard:

```bash
ollama pull llama-guard3:1b
ollama serve  # starts on http://localhost:11434
```

Then configure in `guardex.yaml` or pass directly to `Guard`:

```python
guard = Guard(ollama_url="http://localhost:11434")
```
