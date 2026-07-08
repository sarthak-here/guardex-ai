---
name: Bug report
about: Report a bug in the GuardEx SDK
title: "[BUG] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of the bug.

## Environment

- **GuardEx version**: (e.g., 0.1.0)
- **Python version**: (e.g., 3.11.4)
- **Install extras**: (e.g., `guardex-ai`, `guardex-ai[local]`, `guardex-ai[local,otel]`)
- **OS**: (e.g., Ubuntu 22.04, macOS 14, Windows 11)

## Steps to Reproduce

```python
# Minimal reproducible example
import guardex

guard = guardex.Guard(...)
result = guard.screen(...)  # Describe what happens
```

1. Step 1
2. Step 2
3. ...

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include the full traceback if applicable:

```
Traceback (most recent call last):
  ...
```

## Additional Context

- Relevant policy configuration (redact any secrets or credentials)
- ML provider in use (ONNX, LlamaGuard, GLiNER, etc.)
- Any other context that might help

## Security Note

**If this bug is a security vulnerability, do NOT open a public issue.**
Please follow the responsible disclosure process in [SECURITY.md](../../SECURITY.md).
