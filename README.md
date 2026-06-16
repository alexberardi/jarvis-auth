# jarvis-auth

FastAPI authentication and identity service for Jarvis. It handles user registration, login, JWT access/refresh tokens (hashed refresh tokens), households, app-to-app credentials, node validation, and internal endpoints used by other services to validate JWTs, apps, and nodes. It also exposes a shared settings router.

Runs on **port 7701**.

## Requirements

- Python 3.11+
- Docker & Docker Compose (recommended)
- PostgreSQL (the service uses Postgres + Alembic migrations; the `DATABASE_URL` uses `psycopg2`)

## Setup & run (Docker — recommended)

This service is managed with Poetry (`pyproject.toml` / `poetry.lock`) — there is **no `requirements.txt`**.

```bash
cp .env.example .env   # then edit values (see below)

# Development (hot reload, mounts the repo):
./run.sh               # add --build to rebuild, --rebuild for a clean no-cache build

# Production:
./run-prod.sh          # add --build to rebuild
```

`run.sh` runs `docker compose -f docker-compose.dev.yaml up`. The container listens on `8000` internally and is published on the host as `${JARVIS_AUTH_PORT:-7701}`. Alembic migrations (`alembic upgrade head`) run automatically before Uvicorn starts.

- Swagger UI: http://localhost:7701/docs
- Health: http://localhost:7701/health

If you have no Postgres on the host, you can run a bundled one with the compose `standalone` profile:

```bash
docker compose -f docker-compose.dev.yaml --profile standalone up
```

## Setup & run (local, without Docker)

```bash
poetry install
poetry run alembic upgrade head
poetry run uvicorn jarvis_auth.app.main:app --reload --port 7701
```

## Environment

Copy `.env.example` to `.env`. The active configuration is defined in `jarvis_auth/app/core/settings.py`:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `AUTH_SECRET_KEY` | yes | — | Secret for signing/verifying JWTs. **Must match every other Jarvis service that validates JWTs.** |
| `AUTH_ALGORITHM` | no | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | no | `14` | Refresh token lifetime |
| `REFRESH_TOKEN_GRACE_SECONDS` | no | `10` | Grace window for refresh-token rotation |
| `DATABASE_URL` | yes | — | PostgreSQL connection string (`postgresql+psycopg2://...`) |
| `JARVIS_AUTH_ADMIN_TOKEN` | yes | — | Master admin token for `/admin/*` endpoints |
| `JARVIS_AUTH_PORT` | no | `7701` | Host port the container is published on |

> Note: an older `AUTH_SECRET_KEY` was historically documented as `SECRET_KEY` and the port as `8000` — both are stale. The code uses `AUTH_SECRET_KEY` and the service is reached on `7701`.

## API examples

- Register:
```bash
curl -X POST http://localhost:7701/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"user1","password":"password123"}'
```

- Login:
```bash
curl -X POST http://localhost:7701/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

- Me:
```bash
curl http://localhost:7701/auth/me \
  -H "Authorization: Bearer <access_token>"
```

- Refresh:
```bash
curl -X POST http://localhost:7701/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Testing

```bash
poetry run pytest
```
