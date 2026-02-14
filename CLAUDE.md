# jarvis-auth

FastAPI authentication microservice with JWT tokens, user management, and app-to-app credentials.

## Quick Reference

```bash
# Setup
poetry install
cp .env.example .env
alembic upgrade head

# Run (port 8007 via docker, 8000 direct)
docker-compose up --build
# or: uvicorn jarvis_auth.app.main:app --reload

# Test
pytest
```

## Architecture

```
jarvis_auth/app/
├── main.py              # FastAPI app, middleware
├── api/
│   ├── auth.py          # Register, login, refresh, logout
│   ├── admin_app_clients.py  # App credential management
│   ├── admin_nodes.py   # Node management
│   └── internal.py      # Internal endpoints
├── db/
│   ├── models.py        # User, RefreshToken, AppClient, Node
│   └── session.py       # Database connection
└── core/
    ├── logging.py       # Jarvis logging setup
    └── security.py      # JWT, password hashing
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `SECRET_KEY` | - | JWT signing key (required) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | 30 | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | 7 | Refresh token lifetime |
| `JARVIS_APP_ID` | jarvis-auth | App-to-app ID for logging |
| `JARVIS_APP_KEY` | - | App-to-app key for logging |
| `JARVIS_LOG_CONSOLE_LEVEL` | WARNING | Console log level |
| `JARVIS_LOG_REMOTE_LEVEL` | DEBUG | Remote log level |

## API Endpoints

**User Auth:**
- `POST /auth/register` → Create user
- `POST /auth/login` → Get access + refresh tokens
- `GET /auth/me` → Current user (requires Bearer token)
- `POST /auth/refresh` → Refresh access token
- `POST /auth/logout` → Revoke refresh token

**App-to-App (Admin):**
- `POST /admin/app-clients` → Create app credentials
- `GET /admin/app-clients` → List app clients

**Internal:**
- `POST /internal/validate-app` → Validate app credentials

## App-to-App Authentication

Other services authenticate via headers:
```
X-Jarvis-App-Id: ocr-service
X-Jarvis-App-Key: <app-key>
```

Validate by calling `/internal/validate-app`.

## Dependencies

**Python Libraries:**
- FastAPI, SQLAlchemy, Alembic (migrations)
- python-jose (JWT), passlib (bcrypt)
- httpx, jarvis-log-client

**Service Dependencies:**
- ✅ **Required**: PostgreSQL - Database for users, tokens, app clients, nodes
- ⚠️ **Optional**: `jarvis-logs` (8006) - Centralized logging (degrades to console if unavailable)
- ⚠️ **Optional**: `jarvis-config-service` (8013) - Service discovery

**Used By:**
- `jarvis-command-center` - Node authentication validation
- `jarvis-whisper-api` - Node authentication validation
- `jarvis-ocr-service` - App-to-app authentication validation
- `jarvis-tts` - Node authentication validation
- `jarvis-logs` - App-to-app authentication validation
- `jarvis-settings-server` - JWT validation (superuser)
- `jarvis-admin` - User login and JWT tokens
- `jarvis-mcp` - Service discovery and health checks

**Impact if Down:**
- ❌ No new user logins
- ❌ No app-to-app authentication validation
- ❌ No node authentication validation
- ✅ Existing JWT tokens continue to work (validated locally by services)
- ✅ Services with cached auth continue temporarily
