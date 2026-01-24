# PRD: Jarvis Auth — FastAPI Authentication Service (MVP + Dockerized)

You are building a **standalone FastAPI authentication service**, named `jarvis-auth`, that will provide login/registration for the Jarvis Recipes mobile app and eventually other Jarvis microservices.

This MVP **must be Dockerized** so it can run via Docker Compose alongside the rest of the Jarvis infrastructure.

---

## 🎯 MVP Goals

- User registration and login with **email + password**
- Secure password hashing + JWT access tokens
- Refresh token issuance + validation
- `/auth/me` endpoint to retrieve current user
- Docker + Docker Compose support
- Basic automated tests for registration/login/me/refresh

**No UI, no password reset, no roles** yet.

---

## 🧱 Tech Stack & Core Dependencies

- Python 3.11+
- FastAPI
- SQLAlchemy + Alembic
- passlib[bcrypt] for password hashing
- python-jose or pyjwt for JWT signing
- pydantic BaseSettings for env config
- pytest + httpx TestClient
- Uvicorn ASGI server

---

## 🐳 Dockerization Requirements

Deliver:
1. **Dockerfile** in repository root:
   - Multi-stage build recommended
   - Production-ready container using uvicorn (no `--reload`)
   - EXPOSE port 8000

2. **docker-compose.yml** (top-level):
   - Services:
     - `auth-api` (FastAPI app)
     - `db` (Postgres)
   - Example environment variables should be wired via `.env`
   - Ensure Alembic migrations run automatically on container start
     - Can be run in entrypoint or startup script

3. **Environment Variables**
   Create `.env.example` with:
   ```bash
   SECRET_KEY=changeme
   ACCESS_TOKEN_EXPIRE_MINUTES=15
   REFRESH_TOKEN_EXPIRE_DAYS=7
   DATABASE_URL=postgresql+psycopg2://postgres:postgres@db:5432/jarvis_auth_db
   ALGORITHM=HS256
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=postgres
   POSTGRES_DB=jarvis_auth_db

4.	README section:
	•	Commands for: docker-compose up --build
    •	Example requests for testing the API

📂 Project Structure
jarvis_auth/
  app/
    __init__.py
    main.py
    core/
      config.py
      security.py
    db/
      base.py
      session.py
      models.py
    schemas/
      auth.py
      user.py
    api/
      __init__.py
      deps.py
      routes/
        auth.py
        users.py
    services/
      auth_service.py
      user_service.py
  alembic/
    env.py
    versions/
      (initial migration)
  tests/
    __init__.py
    test_auth_flow.py
Dockerfile
docker-compose.yml
alembic.ini
requirements.txt or pyproject.toml
README.md
.env.example

🧬 Database Models

User Model
	•	id (PK)
	•	email (unique, indexed)
	•	username (unique, indexed)
	•	password_hash
	•	is_active (bool)
	•	created_at / updated_at timestamps

RefreshToken Model
	•	id (PK)
	•	user_id (FK to user)
	•	token (string; hashed or opaque)
	•	expires_at (datetime)
	•	revoked (bool)

⸻

🔐 Security Logic

Helpers in core/security.py:
	•	hash_password(password: str) -> str
	•	verify_password(plain: str, hashed: str) -> bool
	•	create_access_token(data, expires_delta)
	•	create_refresh_token(data, expires_delta)
	•	decode_token(token)

Config in core/config.py loaded from env.

JWT contents:
	•	sub: user id
	•	email: user email
	•	exp: expiry
	•	Signed with SECRET_KEY using HS256

⸻

🧾 API Endpoints

POST /auth/register
	•	Body: { email, username, password }
	•	Returns user info (no password)

POST /auth/login
	•	Validates password
	•	Issues:
	•	access_token (short-lived JWT)
	•	refresh_token (stored in DB)

POST /auth/refresh
	•	Validates refresh token
	•	Issues new access token

GET /auth/me
	•	Requires Authorization: Bearer <token>
	•	Returns current user info

POST /auth/logout (optional stub)
	•	Marks refresh token as revoked

⸻

📌 FastAPI Dependencies

api/deps.py:
	•	get_db() → DB session
	•	get_current_user() → decode JWT, fetch user, fail with 401 if invalid

⸻

🧪 Testing Requirements

Create tests/test_auth_flow.py with tests:
	1.	Register new user → expect 200 + user info
	2.	Login → expect access + refresh tokens
	3.	/auth/me:
	•	No token → 401
	•	Valid token → user info
	4.	Refresh flow:
	•	Login → get refresh token
	•	Call /auth/refresh → new access token

Tests should use in-memory SQLite or temp file; not Postgres.

⸻

🚀 Running the App

README must include:
docker-compose up --build
# API will be available on http://localhost:8007
# Swagger at http://localhost:8007/docs

🔮 Future Extensions (do NOT implement yet)
	•	Multi-service API keys
	•	Roles & permissions
	•	Email verification
	•	Password resets
	•	Session revocation UI
	•	Rate limiting / brute-force protection

Ensure code is modular to support expansion.

⸻

✔️ Deliverables for MVP + Docker

When done, service should:
	1.	Build and run fully via Docker Compose
	2.	Auto-run Alembic migrations on startup
	3.	Support register/login/me/refresh endpoints
	4.	Persist users + refresh tokens
	5.	Use secure password hashing + JWT signing
	6.	Include passing tests for core flows

After completing these tasks, stop and request reviewer approval before adding advanced auth features.

⸻

End of PRD — Follow exactly.