#!/usr/bin/env bash
# The gate: lint, format, then the tests.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
uv sync --locked
.venv/bin/ruff check src tests examples scripts
.venv/bin/ruff format --check src tests examples scripts
.venv/bin/python -m pytest "$@"
