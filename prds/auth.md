

# Auth Service PRD — jarvis-auth

This document defines the core authentication responsibilities and API requirements for the **jarvis-auth** service in the Jarvis Recipes ecosystem.  
It issues and refreshes JWT access tokens consumed by other services and the mobile app.

---

## Goals

- Authenticate users via email + password.
- Create new user accounts.
- Issue **JWT access tokens** (HS256 signed).
- Issue **refresh tokens** for session continuity.
- Validate refresh tokens and rotate access tokens.
- Expose user identity (optional: `/auth/me` for later phases).

jarvis-auth is the **source of truth** for:
- user credentials
- token issuing
- refresh token state

jarvis-auth does **not**:
- Store recipes
- Verify JWTs for other services
- Manage authorization rules for recipes

---

## JWT Token Model

### Access Token (JWT)

- Algorithm: **HS256**
- Signed using shared secret: `AUTH_SECRET_KEY`
- Recommended expiry: **15–30 minutes**

Required claims:
- `sub`: User ID (string)
- `email`: User email
- `exp`: Expiration timestamp (UTC)

Example decoded payload:

```json
{
  "sub": "1",
  "email": "alex@example.com",
  "exp": 1733372800
}
```

### Refresh Token

- Returned alongside access token at **login** and **registration**
- Long‑lived (e.g. 7–30 days)
- Should be stored in DB and tied to user
- Acceptable formats:
  - Opaque UUID
  - OR a JWT (but opaque preferred for MVP)
- Only **jarvis-auth** sees the refresh token

The mobile app will:
- Store refresh token securely
- Use refresh token ONLY to request new access token via `/auth/refresh`

---

## Environment Variables

jarvis-auth **must** read these from environment:

```bash
AUTH_SECRET_KEY="a_long_random_secure_string"
AUTH_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES="30"
REFRESH_TOKEN_EXPIRE_DAYS="14"   # optional
```

These must match the same values in **jarvis-recipes** for signature verification.

Failure to supply these values should prevent the server from starting.

---

## Public API Endpoints

### `POST /auth/register`
Create new user and return tokens.

**Request**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "username": "OptionalUsername"
}
```

**Response**
```json
{
  "access_token": "<jwt>",
  "refresh_token": "<refresh>",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "username": "OptionalUsername"
  }
}
```

---

### `POST /auth/login`
Authenticate user and return tokens.

**Request**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response** — same as register

Error conditions:
- Invalid credentials → `400` or `401` w/ message

---

### `POST /auth/refresh`
Must validate refresh token and issue a new access token.

**Request**
```json
{
  "refresh_token": "<stored_refresh_token>"
}
```

**Response**
```json
{
  "access_token": "<new_jwt>",
  "refresh_token": "<new_or_same_refresh_token>",
  "token_type": "bearer"
}
```

Invalid or missing refresh token → `401`

---

### Future (Phase 2)
Not required for MVP:
- `POST /auth/logout` — revoke refresh token
- `GET /auth/me` — return user profile without issuing new token

---

## Token Functions to Implement

Inside a `utils` or `security` module:

- `create_access_token(payload: dict) -> str`
- `create_refresh_token(user_id: int) -> str`
- `decode_token(token: str) -> dict | raises` (for internal use only)

All signing must use:
```python
settings.auth_secret_key
settings.auth_algorithm
```

---

## Database

Minimum user table:

| column | type | notes |
|--------|------|-------|
| id | int PK | |
| email | string unique | |
| username | string nullable | |
| hashed_password | string | |
| created_at | datetime | |

Refresh token storage (optional MVP) may be added later.

---

## Password Handling

- Must store **hashed passwords** (bcrypt recommended)
- Do not log plaintext passwords
- Compare via constant‑time check

---

## Error Handling

- Never expose internal errors or SQL exceptions in HTTP response bodies
- Provide friendly messages:
  - `{"detail": "Invalid email or password"}`

---

## Testing Requirements

Test the following:
1. Register with valid values → token pair returned
2. Login with correct credentials → token pair returned
3. Login with wrong password → error
4. Decode returned JWT → contains correct `sub`, `email`, `exp`
5. Refresh with valid refresh token → new access token returned
6. Refresh with invalid token → 401

---

## Summary

jarvis-auth is responsible for:
- user registration + login
- issuing and refreshing JWT access tokens
- hashing and validating passwords

It is **not** responsible for:
- JWT validation in other services
- recipe data
- authorization logic outside identity

This PRD should be used by the assistant inside Cursor to generate the auth endpoints and token logic for the jarvis-auth project.