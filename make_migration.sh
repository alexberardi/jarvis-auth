#!/usr/bin/env bash
set -euo pipefail

# Create a new Alembic revision (autogenerate from models) using Python helper
# Usage: ./make_migration.sh "add new table"
# Requires: .venv with alembic, sqlalchemy, psycopg2-binary, python-dotenv installed

if [ $# -lt 1 ]; then
  echo "Usage: $0 \"message for migration\""
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/.venv/bin/python"

if [ -x "$VENV_PYTHON" ]; then
    "$VENV_PYTHON" scripts/make_migration.py "$*"
else
    echo "Error: .venv not found. Create it with:"
    echo "  python3 -m venv .venv"
    echo "  .venv/bin/pip install alembic sqlalchemy psycopg2-binary python-dotenv pydantic pydantic-settings"
    exit 1
fi

