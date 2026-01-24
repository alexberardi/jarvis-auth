#!/usr/bin/env bash
set -euo pipefail

# Apply latest Alembic migrations using Python helper
# Requires: .venv with alembic, sqlalchemy, psycopg2-binary, python-dotenv installed

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/.venv/bin/python"

if [ -x "$VENV_PYTHON" ]; then
    "$VENV_PYTHON" scripts/apply_migrations.py
else
    echo "Error: .venv not found. Create it with:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install alembic sqlalchemy psycopg2-binary python-dotenv pydantic pydantic-settings"
    exit 1
fi

