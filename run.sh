#!/usr/bin/env bash
set -euo pipefail

# Start the auth stack (API + Postgres) using docker-compose.
# Rebuilds images if needed, then detaches.
docker compose up --build -d

