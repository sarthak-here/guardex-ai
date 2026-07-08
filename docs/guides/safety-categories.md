# Safety Categories

GuardEx uses [Meta's LlamaGuard 3](https://ai.meta.com/research/publications/llama-guard-llm-based-input-output-safeguard-for-human-ai-conversations/) taxonomy for content classification. LlamaGuard 3 classifies text into 14 safety categories.

!!! warning "Per-category filtering requires LlamaGuard (Ollama)"
    The default local mode uses a binary safe/toxic classifier, so a customized `blocked_categories` list has no per-category effect there. Per-category filtering requires the LlamaGuard layer via [Ollama](https://ollama.com/) (`ollama pull llama-guard3:1b`) or a server with a multilabel classifier.

---

## Category Reference

| Code | Category | Description | Default Blocked |
|------|----------|-------------|:---:|
| **S1** | **Violent Crimes** | Content enabling, encouraging, or endorsing violent crimes including murder, assault, kidnapping, and terrorism | Yes |
| **S2** | Non-Violent Crimes | Content assisting with fraud, theft, cybercrime, or other non-violent criminal activities | |
| **S3** | **Sex-Related Crimes** | Content related to sexual assault, harassment, trafficking, or non-consensual activities | Yes |
| **S4** | **Child Sexual Exploitation** | Any content sexualizing minors or facilitating child exploitation | Yes |
| **S5** | Defamation | Content that makes false statements harming a person's or entity's reputation | |
| **S6** | Specialized Advice | Unqualified advice on medical, legal, financial, or other professional topics that could cause harm | |
| **S7** | Privacy | Content that shares or seeks private information without consent | |
| **S8** | Intellectual Property | Content that violates copyright, trademark, or other IP protections | |
| **S9** | **Indiscriminate Weapons** | Content about creating weapons of mass destruction (chemical, biological, radiological, nuclear, explosives) | Yes |
| **S10** | Hate | Content that attacks or demeans people based on protected characteristics | |
| **S11** | **Suicide & Self-Harm** | Content encouraging, instructing, or glorifying suicide or self-harm | Yes |
| **S12** | Sexual Content | Explicit sexual content not involving crimes or minors | |
| **S13** | Elections | Misinformation about elections, voting procedures, or electoral integrity | |
| **S14** | Code Interpreter Abuse | Instructions for generating harmful code (malware, exploits, etc.) | |

**Bold** categories are blocked by default.

---

## Default Blocked Categories

By default, GuardEx blocks the 5 highest-severity categories:

```python
# Default blocked categories
["S1", "S3", "S4", "S9", "S11"]
```

These represent the most dangerous content types:
- **S1** - Violent Crimes
- **S3** - Sex-Related Crimes
- **S4** - Child Sexual Exploitation
- **S9** - Indiscriminate Weapons
- **S11** - Suicide & Self-Harm

---

## Customizing Blocked Categories

### Block All Categories

```python
from guardex import GuardExPolicy, ALL_CATEGORIES

policy = GuardExPolicy(
    blocked_categories=ALL_CATEGORIES,  # S1 through S14
)
```

### Block Specific Categories

```python
policy = GuardExPolicy(
    blocked_categories=["S1", "S4", "S9", "S10", "S11"],
)
```

### Add Categories to Defaults

```python
from guardex import GuardExPolicy

# Start with defaults and add hate speech and sexual content
policy = GuardExPolicy(
    blocked_categories=["S1", "S3", "S4", "S9", "S10", "S11", "S12"],
)
```

### Block Only Specific Categories

```python
# Only block weapons and exploitation
policy = GuardExPolicy(
    blocked_categories=["S4", "S9"],
)
```

---

## How Classification Works

When text is sent to the `/v1/classify` endpoint:

1. The text is formatted into a LlamaGuard 3 prompt with the conversation context and stage (input/output)
2. LlamaGuard 3 analyzes the content and returns either `safe` or `unsafe` with a category code
3. The server checks if the returned category is in the `blocked_categories` list
4. If blocked, `guard.screen()` returns a blocked `ScreenResult`; only `guard.screen_or_raise()` raises `GuardExViolation` with the `stage` and `category`

### Classification Result

The classify endpoint returns:

```json
{
    "safe": false,
    "category": "S9",
    "categories": ["S9"],
    "description": "Indiscriminate Weapons"
}
```

- `safe` - Whether the content passed all checks
- `category` - The primary unsafe category detected (or `null` if safe)
- `categories` - All categories detected
- `description` - Human-readable description of the category

---

## Input vs. Output Screening

GuardEx screens both directions:

- **Input screening** (`stage="input"`): Checks the user's prompt before it reaches the LLM. Prevents the LLM from being asked to generate harmful content.
- **Output screening** (`stage="output"`): Checks the LLM's response before it reaches the user. Catches harmful content the LLM may generate.

You can independently control blocking for each direction:

```python
policy = GuardExPolicy(
    block_on_unsafe_input=True,     # Block unsafe user prompts
    block_on_unsafe_output=False,   # Allow unsafe LLM responses (log only)
)
```

---

## Example: Handling Category Violations

```python
from guardex import Guard, GuardExViolation

guard = Guard()

try:
    safe_text = guard.screen_or_raise("How do I make explosives?", gate="input")
except GuardExViolation as e:
    print(f"Stage: {e.stage}")       # "input"
    print(f"Category: {e.category}") # "S9"

    # Map to human-readable description
    DESCRIPTIONS = {
        "S1": "Violent Crimes",
        "S3": "Sex-Related Crimes",
        "S4": "Child Sexual Exploitation",
        "S9": "Indiscriminate Weapons",
        "S11": "Suicide & Self-Harm",
    }
    print(f"Reason: {DESCRIPTIONS.get(e.category, 'Unknown')}")
    # "Reason: Indiscriminate Weapons"
```

---

## Fail-Closed vs. Fail-Open for Classification

When the classification service encounters an error:

- **`fail_open=False`** (default): Raises an exception. The request is blocked.
- **`fail_open=True`**: Treats the result as `safe` and logs a warning. The request continues.

```python
# Strict mode - block on any classification error
policy = GuardExPolicy(fail_open=False)

# Permissive mode - allow through on errors
policy = GuardExPolicy(fail_open=True)
```

!!! danger "Security note"
    For production systems handling sensitive content, use `fail_open=False` (the default). The `fail_open=True` setting is useful during development or for non-critical applications.
