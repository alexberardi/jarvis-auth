# PRD: App-to-App Authentication for Jarvis Services

## 1. Overview

We want a simple, secure way for **Jarvis microservices** (e.g. `llm-proxy`, `jarvis-recipes`, future services) to authenticate **to `jarvis-auth` and to each other (via `jarvis-auth`)** using **app-level credentials**, separate from user auth.

This PRD defines:

- An **app-to-app auth model** based on API keys.
- How keys are **created, stored, validated, and rotated**.
- A minimal set of **admin endpoints** to manage app keys using an **admin token**.
- How other services (starting with `llm-proxy`) use these keys.

The implementation lives in the `jarvis-auth` project.

---

## 2. Goals

1. **Support service-to-service authentication**
   - Allow trusted services (e.g. `llm-proxy`) to authenticate themselves to `jarvis-auth` using a key.
   - Distinct from user-level authentication / JWTs.

2. **Simple API key mechanism**
   - Use a straightforward header-based API key for internal services.
   - Small blast radius, minimal moving parts, easy to debug.

3. **Centralized validation in `jarvis-auth`**
   - `jarvis-auth` is the source of truth for which apps exist and which keys are valid.
   - Other services call into `jarvis-auth` with an app key when they need:
     - to verify user tokens,
     - to call internal auth-protected endpoints,
     - or later, to access other shared infrastructure.

4. **Key rotation via admin token**
   - Provide **admin-only endpoints** to:
     - Create app keys
     - Rotate (regenerate) app keys
     - Revoke (disable) app keys
   - Admin endpoints are protected by a separate **`ADMIN_API_TOKEN`-style secret**.

5. **Secure storage**
   - Store **only hashed keys** in the DB.
   - Raw keys are shown **once on creation/rotation** and must be persisted by the caller.

6. **Extensibility**
   - Design should allow future enhancements, e.g.:
     - app roles/scopes
     - per-key rate limits
     - audit logging

---

## 3. Non-goals

1. **No full-blown OAuth2**
   - We are not implementing OAuth2 / mTLS or complex JWT-based app auth in this iteration.

2. **No dynamic trust federation**
   - Trust is **static and explicit**: if an app has a valid key, it is trusted.

3. **No UI for key management (yet)**
   - Management is via **admin HTTP endpoints** authenticated with an admin token.

4. **No cross-service authorization logic in this PRD**
   - This PRD covers **authentication** (proving which app is calling), not per-app authorization decisions.

---

## 4. Trust Model

- `jarvis-auth` is the **central authority** for:
  - User authentication.
  - App identity and app keys.

- Internal services (e.g. `llm-proxy`, `jarvis-recipes`, future `jarvis-logging`, etc.) are **Jarvis apps**.
  - Each app has a **unique app id** (e.g. `llm-proxy`) and **one active secret key**.
  - Apps authenticate to `jarvis-auth` by sending their key in a header.

- An **admin token** (single secret) protects key management endpoints.
  - This is configured in `jarvis-auth` via env var.
  - Only infrastructure / trusted admin scripts should know this token.

---

## 5. API Key Design

### 5.1 Header format

App-to-app requests to `jarvis-auth` will include:

```http
X-Jarvis-App-Id: llm-proxy
X-Jarvis-App-Key: <random-long-secret>
```

- `X-Jarvis-App-Id` is a short identifier for the calling app.
- `X-Jarvis-App-Key` is a high-entropy secret string.

Alternative (future): support a compact `Authorization: JarvisApp <app_id>:<key>` format. For now, the two-header approach is simpler and explicit.

### 5.2 Key properties

- Length: at least **32 bytes** of randomness, base64 or hex encoded.
- Generated using a cryptographically secure RNG (e.g. `secrets.token_urlsafe(48)` in Python).
- Stored **hashed** in the database:
  - Use a strong hash (e.g. `bcrypt` or `argon2`) to avoid key recovery on DB compromise.
  - `app_id` + `key_hash` pairs uniquely identify an app key.

### 5.3 Validation semantics

- On each protected request, `jarvis-auth` will:
  1. Read `X-Jarvis-App-Id` and `X-Jarvis-App-Key`.
  2. Look up the corresponding app record.
  3. Compare the provided key against the stored hash using a constant-time comparison.
  4. Verify that the app and key are **active**.

- If valid, the request context gets `request.state.app_id = <app_id>` (or equivalent).
- If invalid, return `401 Unauthorized` with a JSON error describing the problem at a high level.

---

## 6. Data Model

Add a new table for app-level credentials. Exact ORM details will depend on the existing models, but conceptually:

```python
# Pseudocode / conceptual model
class AppClient(Base):
    __tablename__ = "app_clients"

    id: int
    app_id: str        # e.g. "llm-proxy", unique
    name: str          # human-readable name/description
    key_hash: str      # hashed app key (bcrypt/argon2)
    is_active: bool
    created_at: datetime
    updated_at: datetime
    last_rotated_at: datetime | None
```

Notes:

- `app_id` is what the client sends in `X-Jarvis-App-Id`.
- We store only `key_hash`, never the raw key.
- Multiple keys per app are **not** needed for v1 (keep it simple: one active key per app).

---

## 7. Admin Token & Admin Endpoints

### 7.1 Admin token

Configure an **admin API token** for `jarvis-auth`:

- Env var: `JARVIS_AUTH_ADMIN_TOKEN` (name can be adjusted to match existing conventions).
- Value: long random secret (at least 32 bytes).
- Requests to admin endpoints must include:

```http
X-Jarvis-Admin-Token: <admin-token>
```

If the header is missing or mismatched, return `401 Unauthorized`.

### 7.2 Admin endpoints

All endpoints prefixed with `/admin/app-clients` (final path can be adjusted to match existing patterns).

#### 7.2.1 Create app client

**Endpoint:** `POST /admin/app-clients`

**Auth:** `X-Jarvis-Admin-Token`

**Body:**

```json
{
  "app_id": "llm-proxy",
  "name": "LLM Proxy Service"
}
```

**Behavior:**

- Generate a **new random key**.
- Hash it and store in `app_clients`.
- Return **only once**:

```json
{
  "app_id": "llm-proxy",
  "name": "LLM Proxy Service",
  "key": "<raw-key>",
  "created_at": "...",
  "last_rotated_at": null
}
```

- If `app_id` already exists, return `400 Bad Request`.

> The caller (e.g. devops script) is responsible for securely storing the raw key and distributing it to the target service (e.g. via environment variables or secret manager).

#### 7.2.2 Rotate app client key

**Endpoint:** `POST /admin/app-clients/{app_id}/rotate`

**Auth:** `X-Jarvis-Admin-Token`

**Behavior:**

- Look up `app_id`.
- Generate a **new random key**, hash it, and update `key_hash` and `last_rotated_at`.
- Return the **new raw key** once:

```json
{
  "app_id": "llm-proxy",
  "key": "<new-raw-key>",
  "last_rotated_at": "..."
}
```

- Invalidate the old key immediately.

> Rotation is an admin operation. It is up to deployment tooling to update the target service's environment (`X-Jarvis-App-Key`) in lockstep with this change.

#### 7.2.3 Revoke / deactivate app client

**Endpoint:** `POST /admin/app-clients/{app_id}/revoke`

**Auth:** `X-Jarvis-Admin-Token`

**Behavior:**

- Set `is_active = false` for the given `app_id`.
- Return a confirmation JSON with `app_id` and `is_active`.

After revocation, any requests using that app id will be rejected.

#### 7.2.4 List app clients (basic)

**Endpoint:** `GET /admin/app-clients`

**Auth:** `X-Jarvis-Admin-Token`

**Behavior:**

- Return a list of app clients with **no keys**, only metadata:

```json
[
  {
    "app_id": "llm-proxy",
    "name": "LLM Proxy Service",
    "is_active": true,
    "created_at": "...",
    "last_rotated_at": "..."
  },
  ...
]
```

This is mainly for sanity checks and diagnostics.

---

## 8. App Auth for Protected Endpoints

We introduce a **dependency / decorator** in `jarvis-auth` for app-protected routes.

### 8.1 Dependency behavior

Pseudocode:

```python
async def require_app_client(request: Request) -> AppClient:
    app_id = request.headers.get("X-Jarvis-App-Id")
    app_key = request.headers.get("X-Jarvis-App-Key")

    if not app_id or not app_key:
        raise HTTPException(status_code=401, detail="Missing app credentials")

    app_client = await app_client_repo.get_by_app_id(app_id)
    if not app_client or not app_client.is_active:
        raise HTTPException(status_code=401, detail="Invalid app credentials")

    if not verify_key(app_key, app_client.key_hash):
        raise HTTPException(status_code=401, detail="Invalid app credentials")

    # Attach to request context as needed
    request.state.app_id = app_client.app_id
    return app_client
```

Any endpoint that should be restricted to Jarvis apps (e.g. internal token verification) can include:

```python
@app.post("/internal/some-endpoint")
async def some_endpoint(app_client: AppClient = Depends(require_app_client)):
    ...
```

### 8.2 Integration with llm-proxy

- `llm-proxy` will be registered as an app (e.g. `app_id = "llm-proxy"`).
- Its key will be stored in `llm-proxy`'s environment (e.g. `JARVIS_AUTH_APP_KEY`).
- For any calls to `jarvis-auth`, `llm-proxy` will send:

```http
X-Jarvis-App-Id: llm-proxy
X-Jarvis-App-Key: <value from env>
```

- `jarvis-auth` will use `require_app_client` to validate and authorize those requests.

---

## 9. Error Handling

For app-level auth failures on non-admin endpoints, respond with consistent JSON errors, e.g.:

```json
{
  "detail": "Missing app credentials"
}
```

or

```json
{
  "detail": "Invalid app credentials"
}
```

For admin endpoints, if the admin token is wrong or missing, return:

```json
{
  "detail": "Unauthorized"
}
```

We can refine error codes/messages later; for now, keep them simple to avoid leaking sensitive details.

---

## 10. Security Considerations

1. **Key storage**
   - Store only **hashed keys**.
   - Use a strong password hashing algorithm (e.g. bcrypt, argon2) with appropriate parameters.

2. **Transport security**
   - All traffic between services and `jarvis-auth` should occur over **TLS** (e.g. via internal HTTPS or a secured reverse proxy).

3. **Admin token protection**
   - `JARVIS_AUTH_ADMIN_TOKEN` must only be present in:
     - `jarvis-auth` env
     - Deployment/ops automation that manages keys
   - It must not be shared with regular services.

4. **Rotation & incident response**
   - If an app key is suspected compromised:
     - Use `POST /admin/app-clients/{app_id}/rotate` to generate a new key.
     - Update the app's configuration with the new key.
   - If the admin token is compromised:
     - Rotate it via deployment configuration.
     - Consider rotating all app keys as well.

5. **Rate limiting (future)**
   - We may later add per-app rate limits or anomaly detection for misuse.

---

## 11. Rollout Plan

1. **Schema changes**
   - Add the `app_clients` table.
   - Add migrations as needed.

2. **Implement admin token middleware/dependency**
   - A small dependency that reads `X-Jarvis-Admin-Token` and checks against `JARVIS_AUTH_ADMIN_TOKEN`.

3. **Implement admin endpoints**
   - `POST /admin/app-clients`
   - `POST /admin/app-clients/{app_id}/rotate`
   - `POST /admin/app-clients/{app_id}/revoke`
   - `GET /admin/app-clients`

4. **Implement app auth dependency**
   - `require_app_client` dependency and repository helpers for `app_clients`.

5. **Integrate with protected endpoints**
   - Identify internal endpoints that should require app credentials.
   - Update them to depend on `require_app_client`.

6. **Register llm-proxy as first app client**
   - Use the admin endpoint to create `llm-proxy` app client.
   - Store the returned key in `llm-proxy` env (`JARVIS_AUTH_APP_KEY`).
   - Update `llm-proxy` HTTP client code to send the app headers.

7. **Testing**
   - Unit tests for:
     - Key generation & verification.
     - Admin token enforcement.
     - App credential validation.
   - Integration tests for successful and failed calls from a simulated app.

---

## 12. Future Enhancements / Open Questions

1. **App scopes / roles**
   - Introduce a `scopes` or `roles` field on app clients and enforce them on specific endpoints.

2. **Multiple keys per app**
   - Allow apps to have multiple active keys to support zero-downtime rotation.

3. **Key expiration**
   - Optional expiration dates for keys, with monitoring/reminders.

4. **Audit logging**
   - Log all admin actions (create/rotate/revoke) and possibly all app-authenticated calls for security audits.

5. **UI for key management**
   - A simple web UI (or CLI) for viewing and managing app clients on top of these endpoints.

---

## 13. Implementation Notes

- Follow existing repo style:
  - **Imports at the top of files only**, unless there is a very strong reason for a local import.
- Keep app auth logic centralized:
  - App auth dependency in a dedicated module (e.g. `dependencies/app_auth.py` or similar).
  - Admin token handling in another dedicated module (e.g. `dependencies/admin_auth.py`).
- Do not duplicate key verification logic; expose a single helper (e.g. `verify_key(raw, hashed)`) used everywhere.
