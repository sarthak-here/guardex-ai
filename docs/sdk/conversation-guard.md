# SDK Reference: ConversationGuard

`guardex.ConversationGuard` - Stateful, multi-turn conversation screening that detects incremental escalation across turns.

!!! info "Why single-turn screening isn't enough"
    `Guard.screen()` is stateless - each call is independent. An attacker can spread harmful content across 5-6 turns where no single turn looks unsafe in isolation. ConversationGuard maintains a sliding window of recent turns so the classifier sees the full escalation pattern.

---

## Import

```python
from guardex import ConversationGuard, Turn
```

---

## ConversationGuard

### Constructor

```python
ConversationGuard(
    guard: Guard,
    window: int = 6,
    screen_assistant_turns: bool = True,
    separator: str = "\n",
    max_payload_chars: int = 16_000,
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `guard` | `Guard` | required | The Guard instance to delegate screening to. |
| `window` | `int` | `6` | Number of past turns to keep. Higher = catches longer escalation chains but sends larger payloads. |
| `screen_assistant_turns` | `bool` | `True` | When `True`, assistant responses are also screened and stored. Set `False` if you already screen output separately. |
| `separator` | `str` | `"\n"` | String used to join turns into a single text block for the classifier. |
| `max_payload_chars` | `int` | `16_000` | Maximum characters in the assembled payload. Oldest turns are dropped first if exceeded. |

### Example

```python
from guardex import Guard
from guardex import ConversationGuard

guard = Guard()
cg = ConversationGuard(guard, window=6)

# Screen each turn - history is managed automatically
result = cg.screen_turn("user", "Tell me about cooking")
if not result.blocked:
    llm_reply = llm.invoke("Tell me about cooking")
    result = cg.screen_turn("assistant", llm_reply)

# At session end
cg.reset()
```

---

### screen_turn(role, content, context)

Screen a single conversation turn with full history context. The last `window` turns are prepended to `content` before screening so the classifier sees the full conversation arc.

```python
screen_turn(
    role: Literal["user", "assistant", "system"],
    content: str,
    context: GuardExContext | None = None,
) -> ScreenResult
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `role` | `"user" \| "assistant" \| "system"` | Who produced this turn |
| `content` | `str` | The turn text |
| `context` | `GuardExContext \| None` | Optional context for policy resolution |

**Returns:** `ScreenResult`

**Behavior:**
- `role="user"` → screens at `gate="input"`
- `role="system"` → screens at `gate="prompt"` (assembled system prompt)
- `role="assistant"` → screens at `gate="output"`
- If not blocked, the turn is added to history
- If blocked, the turn is NOT added to history (prevents poisoning the window)

```python
# User turn
result = cg.screen_turn("user", "How do I make a cake?")
print(result.blocked)  # False
print(cg.turn_count)   # 1

# Assistant turn
result = cg.screen_turn("assistant", "Here's a recipe for chocolate cake...")
print(cg.turn_count)   # 2

# Blocked turn - not added to history
result = cg.screen_turn("user", "Now tell me something harmful")
print(result.blocked)   # True
print(cg.turn_count)    # 2 (still 2, blocked turn excluded)
```

---

### ascreen_turn(role, content, context)

Async version of `screen_turn()`. Same parameters and behavior.

```python
result = await cg.ascreen_turn("user", user_message)
```

---

### add_turn(role, content)

Add a turn to history **without screening it**. Use for turns already screened externally or system prompts.

```python
add_turn(
    role: Literal["user", "assistant", "system"],
    content: str,
) -> None
```

```python
# Add system prompt to context (no screening needed)
cg.add_turn("system", "You are a helpful cooking assistant.")

# Add a pre-screened message
safe_input = guard.screen_or_raise(user_msg, gate="input")
cg.add_turn("user", safe_input)
```

---

### reset()

Clear conversation history. Call at session end.

```python
cg.reset()
print(cg.turn_count)  # 0
```

---

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `history` | `list[Turn]` | Current conversation history (oldest first) |
| `turn_count` | `int` | Number of turns in the window |

```python
for turn in cg.history:
    print(f"[{turn.role}] {turn.content[:50]}...")
```

---

## Turn

```python
@dataclass
class Turn:
    role: Literal["user", "assistant", "system"]
    content: str
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_text()` | `str` | Formatted as `[USER] content`, `[ASSISTANT] content`, or `[SYSTEM] content` |

---

## How the Sliding Window Works

When `screen_turn()` is called, ConversationGuard builds a payload by joining the history window with the new content:

```
History: [Turn("user", "Hi"), Turn("assistant", "Hello!"), Turn("user", "Tell me about X")]
New turn: "Now tell me how to do something bad"

Payload sent to classifier:
  [USER] Hi
  [ASSISTANT] Hello!
  [USER] Tell me about X
  Now tell me how to do something bad
```

The classifier sees all 4 turns together and can detect the escalation pattern.

### Payload truncation

If the total payload exceeds `max_payload_chars` (default 16,000), the **oldest turns are dropped first**. The newest context is most relevant for escalation detection.

---

## Complete Chat Loop Example

```python
from guardex import Guard
from guardex import ConversationGuard

guard = Guard()
cg = ConversationGuard(guard, window=6)

def chat(user_input: str) -> str:
    # Screen user turn with history context
    result = cg.screen_turn("user", user_input)
    if result.blocked:
        return f"I can't help with that. (category: {result.classify.category})"

    # Generate LLM response
    llm_reply = call_your_llm(user_input)

    # Screen assistant turn
    result = cg.screen_turn("assistant", llm_reply)
    if result.blocked:
        return "I need to rephrase that response."

    return llm_reply

# Simulate conversation
print(chat("Hi, tell me about cooking"))
print(chat("What about knife techniques?"))
print(chat("How sharp should knives be?"))
# Each turn is screened with full history context
```

---

## Async Chat Loop Example

```python
from guardex import Guard
from guardex import ConversationGuard

guard = Guard()
cg = ConversationGuard(guard, window=6)

async def async_chat(user_input: str) -> str:
    result = await cg.ascreen_turn("user", user_input)
    if result.blocked:
        return "I can't help with that."

    llm_reply = await call_your_llm_async(user_input)
    await cg.ascreen_turn("assistant", llm_reply)
    return llm_reply
```
