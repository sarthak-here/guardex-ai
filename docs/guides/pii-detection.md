# PII Detection

GuardEx detects and handles Personally Identifiable Information (PII) using [GLiNER](https://github.com/urchade/GLiNER) with NVIDIA's `nvidia/gliner-pii` model. In server mode, all PII inference runs server-side - no local models needed. In local mode (`pip install guardex-ai[local]`), PII inference runs in-process using the GLiNER model.

---

## How It Works

```mermaid
flowchart LR
    A[Input Text] --> B[GuardEx Engine]
    B --> C[GLiNER Model]
    C --> D{PII Found?}
    D -->|No| E[Pass Through]
    D -->|Yes, action=mask| F["Replace with [LABEL]"]
    D -->|Yes, action=block| G[Block - check result.pii]
    F --> H[Continue Pipeline]

    style F fill:#f59e0b,color:#000
    style G fill:#ef4444,color:#fff
    style E fill:#22c55e,color:#fff
```

1. Text is sent to the GuardEx engine (local or server)
2. GLiNER runs to detect PII entities with confidence scores
3. Based on your `pii_action` setting:
   - **`mask`**: PII is replaced with `[LABEL]` placeholders (e.g., `john@corp.com` → `[EMAIL]`)
   - **`block`**: The request is blocked - use `guard.screen()` and check `result.pii.has_pii`
4. The processed text continues through the pipeline

---

## Supported Entity Types (31)

GuardEx detects 31 PII entity types across 5 categories. All are enabled by default.

### Personal Information (9)

| Entity Type | Description | Example | Masked As |
|-------------|-------------|---------|-----------|
| `email` | Email addresses | `john@corp.com` | `[EMAIL]` |
| `phone_number` | Phone numbers | `555-123-4567` | `[PHONE_NUMBER]` |
| `name` | Person names | `John Smith` | `[NAME]` |
| `address` | Physical addresses | `123 Main St, NYC` | `[ADDRESS]` |
| `ssn` | Social Security Numbers | `123-45-6789` | `[SSN]` |
| `national_id` | National ID numbers | `AB123456C` | `[NATIONAL_ID]` |
| `passport_number` | Passport numbers | `X12345678` | `[PASSPORT_NUMBER]` |
| `date_of_birth` | Dates of birth | `March 15, 1990` | `[DATE_OF_BIRTH]` |
| `driver_license` | Driver's license numbers | `D123-4567-8901` | `[DRIVER_LICENSE]` |

### Credentials & Secrets (6)

| Entity Type | Description | Example | Masked As |
|-------------|-------------|---------|-----------|
| `password` | Passwords in context | `password is hunter2` | `[PASSWORD]` |
| `user_name` | Usernames / handles | `@johndoe` | `[USER_NAME]` |
| `private_key` | Private keys | `-----BEGIN RSA PRIVATE KEY-----` | `[PRIVATE_KEY]` |
| `jwt_token` | JWT tokens | `eyJhbGciOiJIUzI1NiIs...` | `[JWT_TOKEN]` |
| `auth_header` | Authorization headers | `Bearer sk-abc123...` | `[AUTH_HEADER]` |
| `secret` | Generic secrets | `client_secret=abc123def` | `[SECRET]` |

### API Keys & Tokens (8)

| Entity Type | Description | Example | Masked As |
|-------------|-------------|---------|-----------|
| `api_key` | Generic API keys | `sk-abc123def456...` | `[API_KEY]` |
| `aws_key` | AWS access keys | `AKIAIOSFODNN7EXAMPLE` | `[AWS_KEY]` |
| `github_token` | GitHub tokens | `ghp_xxxxxxxxxxxx` | `[GITHUB_TOKEN]` |
| `slack_token` | Slack tokens | `xoxb-1234-5678-abcdef` | `[SLACK_TOKEN]` |
| `stripe_key` | Stripe API keys | `sk_live_abc123...` | `[STRIPE_KEY]` |
| `google_api_key` | Google API keys | `AIzaSyA...` | `[GOOGLE_API_KEY]` |
| `openai_key` | OpenAI API keys | `sk-proj-abc123...` | `[OPENAI_KEY]` |
| `twilio_sid` | Twilio SIDs | `AC1234567890abcdef` | `[TWILIO_SID]` |

### Financial (3)

| Entity Type | Description | Example | Masked As |
|-------------|-------------|---------|-----------|
| `credit_card` | Credit card numbers | `4111-1111-1111-1111` | `[CREDIT_CARD]` |
| `bank_account` | Bank account numbers | `1234567890` | `[BANK_ACCOUNT]` |
| `iban` | International bank accounts | `GB29NWBK60161331926819` | `[IBAN]` |

### Network & Infrastructure (5)

| Entity Type | Description | Example | Masked As |
|-------------|-------------|---------|-----------|
| `ip_address` | IPv4 addresses | `192.168.1.1` | `[IP_ADDRESS]` |
| `ipv6_address` | IPv6 addresses | `2001:0db8:85a3::8a2e:0370:7334` | `[IPV6_ADDRESS]` |
| `mac_address` | MAC addresses | `00:1B:44:11:3A:B7` | `[MAC_ADDRESS]` |
| `hostname` | Server hostnames | `db-prod-01.internal.corp.com` | `[HOSTNAME]` |
| `database_url` | Database connection strings | `postgres://user:pass@host/db` | `[DATABASE_URL]` |

!!! tip "Custom PII entities"
    Need to detect domain-specific PII (medical record numbers, employee IDs, etc.)? Use `pii_custom_regex` — see [Custom Regex Patterns](#custom-regex-patterns) below.

---

## PII Actions

### Mask (Default)

PII is replaced with `[LABEL]` placeholders. The conversation continues with sanitized text.

```python
from guardex import Guard

guard = Guard()

result = guard.screen("My email is john@corp.com, translate hello to French", gate="input")
print(result.text)
# "My email is [EMAIL], translate hello to French"
print(result.pii.has_pii)       # True
print(result.pii.masked_text)   # "My email is [EMAIL], translate hello to French"
```

### Block

When `pii_action="block"`, the `Guard` class does **not** raise an exception. Instead, use `guard.screen()` and check the result:

!!! note "Guard does not raise PIIViolation"
    `PIIViolation` is only raised by the LangChain wrappers (`GuardedLLM`, `GuardExCallbackHandler`). With the `Guard` class, use `guard.screen()` and check `result.pii.has_pii`.

When `pii_action="block"` and PII is detected, the `ScreenResult` will have:

- `result.blocked` → `True`
- `result.safe` → `False`
- `result.action` → `"block"`
- `result.pii.has_pii` → `True`

If you use `screen_or_raise()` with `pii_action="block"`, it raises `GuardExViolation` (not `PIIViolation`) because the result is blocked.

```python
from guardex import Guard, GuardExPolicy

guard = Guard(policy=GuardExPolicy(pii_action="block"))

result = guard.screen("My SSN is 123-45-6789", gate="input")

if result.pii.has_pii:
    print(f"PII detected at gate: {result.gate}")
    for entity in result.pii.entities:
        print(f"  {entity.label}: score={entity.score:.2f}")
        # ssn: score=0.95
```

---

## Configuring PII Detection

### Enable/Disable PII

```python
from guardex import Guard, GuardExPolicy

# PII enabled (default)
guard = Guard(policy=GuardExPolicy(pii_enabled=True))

# PII disabled
guard = Guard(policy=GuardExPolicy(pii_enabled=False))
```

### Select Specific Entities

Detect only the entities you care about:

```python
# Only detect financial PII
guard = Guard(policy=GuardExPolicy(
    pii_entities=["ssn", "credit_card", "bank_account"],
))

# Only detect contact information
guard = Guard(policy=GuardExPolicy(
    pii_entities=["email", "phone_number", "address"],
))

# Detect everything (default)
from guardex import DEFAULT_PII_ENTITIES
guard = Guard(policy=GuardExPolicy(
    pii_entities=DEFAULT_PII_ENTITIES,
))
```

### Adjust Confidence Threshold

The `pii_threshold` controls how confident the model must be before flagging something as PII:

```python
# High sensitivity (catches more, but may have false positives)
guard = Guard(policy=GuardExPolicy(pii_threshold=0.4))

# Default sensitivity
guard = Guard(policy=GuardExPolicy(pii_threshold=0.85))

# Very strict (fewer detections, fewer false positives)
guard = Guard(policy=GuardExPolicy(pii_threshold=0.95))
```

| Threshold | Behavior |
|-----------|----------|
| 0.3 - 0.6 | High sensitivity - catches most PII but may flag non-PII |
| 0.85 | Default - real PII consistently scores at or above this; the 0.6-0.8 false-positive band is excluded |
| 0.9 - 0.95 | Conservative - only the highest-confidence detections |

### Custom Regex Patterns

`pii_custom_regex` extends the built-in entity list with your own label → regex mappings, for domain-specific PII the GLiNER model doesn't know about (medical record numbers, employee IDs, internal ticket IDs, ...):

```python
from guardex import Guard, GuardExPolicy

guard = Guard(policy=GuardExPolicy(
    pii_custom_regex={
        "employee_id": r"EMP-\d{6}",
        "medical_record_number": r"MRN-[A-Z]{2}\d{8}",
    },
))

result = guard.screen("Patient MRN-AB12345678 was seen by EMP-004821", gate="input")
print(result.text)
# "Patient [MEDICAL_RECORD_NUMBER] was seen by [EMPLOYEE_ID]"
```

The dict key becomes both the entity label and the mask placeholder (uppercased), so `"employee_id"` masks to `[EMPLOYEE_ID]`. Patterns compile with `re.IGNORECASE`.

Pair it with `pii_custom_context_keywords` to boost confidence when a keyword appears near a match:

```python
guard = Guard(policy=GuardExPolicy(
    pii_custom_regex={"employee_id": r"EMP-\d{6}"},
    pii_custom_context_keywords={"employee_id": ["employee", "staff", "badge"]},
))
```

!!! warning "Local mode only"
    `pii_custom_regex` and `pii_custom_context_keywords` only take effect when `Guard` runs in local mode. In server mode (`base_url`/`api_key` set), the server does not accept caller-supplied regex or word lists, so these fields are ignored.

---

## Guard PII Methods

### pii_scan() - Detection Only

```python
guard = Guard()

result = guard.pii_scan("My email is john@corp.com and SSN is 123-45-6789")
print(result.has_pii)  # True
for entity in result.entities:
    print(f"  {entity.label}: score={entity.score:.2f} "
          f"text='{entity.text}' span=({entity.start}, {entity.end})")
```

### pii_mask() - Detection + Masking

```python
guard = Guard()

masked = guard.pii_mask("Call John at john@corp.com or 555-123-4567")
print(masked)
# "Call [NAME] at [EMAIL] or [PHONE_NUMBER]"
```

### screen() - Combined PII + Safety

The `screen()` method combines PII detection with safety classification in a single API call:

```python
guard = Guard()

result = guard.screen("My SSN is 123-45-6789, how do I file taxes?", gate="input")
print(result.pii.has_pii)           # True
print(result.text)                  # "My SSN is [SSN], how do I file taxes?"
print(result.classify.safe)         # True
print(result.action)                # "mask"
```

---

## Using the Direct Client for PII

### PII Scan (Detection Only)

```python
from guardex import GuardExClient

with GuardExClient(base_url="http://localhost:8001") as client:
    result = client.pii_scan("My email is john@corp.com and SSN is 123-45-6789")

    print(result["has_pii"])  # True
    for entity in result["entities"]:
        print(f"  {entity['label']}: score={entity['score']:.2f} "
              f"span=({entity['start']}, {entity['end']})")
```

### PII Mask (Detection + Masking)

```python
with GuardExClient(base_url="http://localhost:8001") as client:
    result = client.pii_mask("Call John at john@corp.com or 555-123-4567")

    print(result["has_pii"])      # True
    print(result["masked_text"])  # "Call [NAME] at [EMAIL] or [PHONE_NUMBER]"
```

---

## PII in Input vs. Output

GuardEx screens PII in both directions:

### Input PII

When PII is detected in the user's prompt:
- **mask**: The text is rewritten with `[LABEL]` placeholders. The LLM never sees the actual PII.
- **block**: The result is blocked - check `result.pii.has_pii` to detect and handle.

### Output PII

When PII is detected in the LLM's response:
- **mask**: The response text is rewritten with placeholders before being returned to the user.
- **block**: The result is blocked - check `result.pii.has_pii` and do not return the response to the user.

---

## PIIResult and PIIEntity Types

The `Guard` class returns typed result objects:

### PIIResult

```python
result = guard.pii_scan("text with PII")

result.has_pii        # bool - whether PII was detected
result.entities       # list[PIIEntity] - detected entities
result.masked_text    # str | None - text with PII replaced (None for pii_scan; populated by screen() and pii_mask())
```

### PIIEntity

```python
for entity in result.entities:
    entity.text    # str - detected text (e.g., "john@example.com")
    entity.label   # str - entity type (e.g., "email")
    entity.score   # float - confidence (0.0-1.0)
    entity.start   # int - character offset
    entity.end     # int - character offset
```

---

## Entity Detection Details

Each detected entity includes:

| Field | Type | Description |
|-------|------|-------------|
| `text` | `str` | The detected PII text (e.g., `"john@corp.com"`) |
| `label` | `str` | Entity type (e.g., `"email"`, `"ssn"`) |
| `score` | `float` | Confidence score (0.0 - 1.0) |
| `start` | `int` | Character offset where the entity starts |
| `end` | `int` | Character offset where the entity ends |

The `start` and `end` offsets allow you to locate the exact position in the original text.
