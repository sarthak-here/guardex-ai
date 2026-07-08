# GuardEx Interactive Notebooks

Three notebooks that run the full GuardEx pipeline in-process - no API keys, no server, no mock data.

| # | Notebook | What you'll do | Time |
|---|---|---|---|
| 01 | [Quickstart](./01_quickstart.ipynb) | Install, first screen, block unsafe content and injection, mask PII, guard an LLM call | 10 min |
| 02 | [PII Detection](./02_pii_detection.ipynb) | 31 entity types, mask vs block, thresholds, deny/allow lists, the reversible PII Vault | 15 min |
| 03 | [Content Safety](./03_content_safety.ipynb) | S1-S14 taxonomy, the classification cascade, observe-only rollout, injection defense, refusals | 15 min |

## Run in Colab

| Notebook | Badge |
|---|---|
| 01 Quickstart | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/atliq/guardex-ai/blob/main/docs/notebooks/01_quickstart.ipynb) |
| 02 PII Detection | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/atliq/guardex-ai/blob/main/docs/notebooks/02_pii_detection.ipynb) |
| 03 Content Safety | [![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/atliq/guardex-ai/blob/main/docs/notebooks/03_content_safety.ipynb) |

## Run in Binder

[![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/atliq/guardex-ai/main?labpath=docs%2Fnotebooks%2F01_quickstart.ipynb)

Opens notebook 01; use the JupyterLab file browser for the others.

## Run locally

```bash
pip install 'guardex-ai[local]' jupyter
jupyter lab docs/notebooks/
```

The first `Guard()` construction downloads about 250 MB of models to `~/.cache/`; every run after that is warm.
