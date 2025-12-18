# Jarvis Auth Service (MVP)

FastAPI authentication microservice providing registration, login, JWT access tokens, hashed refresh tokens, and a minimal user info endpoint. Dockerized for use alongside Postgres via docker-compose.

## Requirements
- Python 3.11+
- Docker & Docker Compose

## Setup (local)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn jarvis_auth.app.main:app --reload
```

Swagger UI: http://localhost:8000/docs

## Environment
Copy `.env.example` to `.env` and adjust as needed.
```
SECRET_KEY=changeme
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
DATABASE_URL=postgresql+psycopg2://postgres:postgres@db:5432/authdb
ALGORITHM=HS256
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=authdb
```

## Docker Compose
```bash
docker-compose up --build
```
API available at http://localhost:8007 (Swagger at http://localhost:8007/docs). Alembic migrations run automatically before startup.

## API Examples
- Register:
```bash
curl -X POST http://localhost:8007/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","username":"user1","password":"password123"}'
```

- Login:
```bash
curl -X POST http://localhost:8007/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

- Me:
```bash
curl http://localhost:8007/auth/me \
  -H "Authorization: Bearer <access_token>"
```

- Refresh:
```bash
curl -X POST http://localhost:8007/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

- Logout (revokes refresh token):
```bash
curl -X POST http://localhost:8007/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Testing
```
pytest
```

Tests use an in-memory SQLite database and cover register, login, /auth/me (401 + success), and refresh flow.

# jarvis-auth
