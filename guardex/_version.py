# SPDX-License-Identifier: Apache-2.0
"""Single source for the package version.

Resolves the installed distribution version via ``importlib.metadata`` and
falls back to a static value when the package is not installed
(e.g. running from an unbuilt source checkout).
"""
from __future__ import annotations

import logging

# Keep in sync with ``[project] version`` in pyproject.toml.
FALLBACK_VERSION = "0.1.1"

logger = logging.getLogger(__name__)


def get_package_version() -> str:
    """Return the installed ``guardex-ai`` version, or ``FALLBACK_VERSION`` if
    the package is not installed.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError as e:
        logger.debug("importlib.metadata unavailable: %s", e)
        return FALLBACK_VERSION
    try:
        return version("guardex-ai")
    except PackageNotFoundError as e:
        logger.debug("'guardex-ai' not installed as a distribution: %s", e)
        return FALLBACK_VERSION
