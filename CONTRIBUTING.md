# Contributing to GuardEx

Thank you for considering contributing to GuardEx! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.10+
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/atliq/guardex-ai.git
cd guardex

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install SDK in development mode with all optional extras
pip install -e ".[dev,local]"

# Run SDK tests
pytest tests/ -v
```

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/atliq/guardex-ai/issues) to avoid duplicates
2. Use the bug report template when creating a new issue
3. Include: Python version, SDK version, steps to reproduce, expected vs actual behavior

### Suggesting Features

1. Open a GitHub issue with the "feature request" label
2. Describe the use case and expected behavior
3. If possible, include example API usage

### Submitting Pull Requests

1. **Fork** the repository and create a feature branch from `main`
2. **Link** your PR to an existing issue (or create one first for features)
3. **Write tests** for any new functionality
4. **Run the test suite** before submitting:
   ```bash
   pytest tests/ -v
   ```
5. **Follow the code style**: we use `black` for formatting and `ruff` for linting
6. **Update documentation** if your change affects the public API
7. **Keep PRs focused** - one feature or fix per PR

### Code Style

- **Formatting**: `black` with default settings
- **Linting**: `ruff` with default settings
- **Type hints**: Required for all public API functions
- **Docstrings**: Required for all public classes and methods (Google style)
- **Tests**: Required for all new features and bug fixes

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb: "Add", "Fix", "Update", "Remove"
- Reference issue numbers: "Fix #123: handler tuple unpacking bug"

## Project Structure

```
guardex/
├── guardex/          # Client SDK (pip installable)
│   ├── guard.py          # Main Guard class
│   ├── client.py         # HTTP client
│   ├── policy.py         # Policy configuration
│   └── ...
├── tests/                # SDK test suite
└── docs/                 # Documentation (guides, notebooks, SDK reference)
```

## Branch Strategy

This project uses **`main`** as the default branch. Open PRs against `main`.

- Create a topic branch off `main` (e.g. `feat/pii-regex`, `fix/handler-tuple`).
- Keep PRs small and focused - one feature or fix per PR.
- Rebase (don't merge) `main` into your branch before requesting review.

## Security

If you discover a security vulnerability, **do NOT open a public issue**. Please see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing to GuardEx, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
