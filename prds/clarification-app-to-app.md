# Clarification: What Was Actually Implemented for App-to-App Auth?

> **Instructions for the model working in `jarvis-auth`:**  
> Read this file and answer all of the questions below **in this same file**.  
> Do **not** modify other PRD files while answering. You may read them for context, but all clarifications should be written here.

---

## 1. High-Level Architecture

1.1. For **app-to-app authentication**, where is the **source of truth** for app IDs and keys?
- Is `jarvis-auth` the only service that stores and validates app keys?
- Or do consumer services (like `llm-proxy`, `jarvis-recipes`, etc.) also store app keys or hashes locally?

**Answer:** `jarvis-auth` is the source of truth for app keys (it creates/rotates/revokes and stores only hashed keys in its own DB). Consumer services (like `llm-proxy`, `jarvis-recipes`, etc.) should **not** store their own hashed copies of app keys for inbound validation. Instead, they are expected to forward app credentials to `jarvis-auth` for verification when they need to authenticate other apps.

1.2. When another service (e.g., `llm-proxy`) wants to validate an incoming request from a different Jarvis app, which model is actually implemented right now?
- **Option A:** The consumer service validates `X-Jarvis-App-Id` and `X-Jarvis-App-Key` **locally** against its own allowlist / config.
- **Option B:** The consumer service forwards those headers to `jarvis-auth`, and `jarvis-auth` decides whether they are valid.
- **Option C:** Some hybrid or different approach.

Please describe in 2–3 sentences which option is implemented and how.

**Answer:** Option B is the desired and recommended model going forward. When a consumer service (e.g., `llm-proxy`) wants to validate another Jarvis app’s credentials, it should **forward the app headers to `jarvis-auth`**, which decides whether they are valid. The consuming service then enforces the result (allow/deny) based on jarvis-auth’s response. This centralizes all app-to-app validation logic inside jarvis-auth.

---

## 2. Endpoints Related to App-to-App Auth

2.1. List all endpoints in `jarvis-auth` that are related to app clients or app-to-app auth. For each one, provide:
- HTTP method and path (e.g., `POST /admin/app-clients`)
- Brief description of what it does
- What kind of authentication it expects (admin token, app headers, none)

**Answer:**
- `POST /admin/app-clients` — create app client, returns raw key once; requires `X-Jarvis-Admin-Token`.
- `POST /admin/app-clients/{app_id}/rotate` — rotate key, returns new raw key once; requires `X-Jarvis-Admin-Token`.
- `POST /admin/app-clients/{app_id}/revoke` — set inactive; requires `X-Jarvis-Admin-Token`.
- `GET /admin/app-clients` — list metadata (no keys); requires `X-Jarvis-Admin-Token`.
- `GET /internal/app-ping` — simple protected endpoint to test app auth; requires app headers (`X-Jarvis-App-Id`, `X-Jarvis-App-Key`).

2.2. Is there a **dedicated endpoint** for validating app credentials (for example `GET /internal/verify-app` or similar)?
- If **yes**, document:
  - The method and path
  - What headers it expects
  - The shape of the success response (status code + JSON body)
  - The shape of failure responses (status codes + JSON bodies)
- If **no**, explain how app credentials are validated instead (e.g., only as dependencies on other internal routes).

**Answer:** There is no standalone `/internal/verify-app` endpoint, but `GET /internal/app-ping` effectively serves this purpose and is the intended endpoint for verifying app credentials. It expects `X-Jarvis-App-Id` and `X-Jarvis-App-Key` headers. On success it returns `200` with a JSON body like `{"app_id": "...", "name": "..."}`. On failure it returns `401` with `{"detail": "Missing app credentials"}` or `{"detail": "Invalid app credentials"}`. Consumer services should call `/internal/app-ping` to centrally validate app credentials instead of validating them locally.

---

## 3. Header Contract

3.1. Confirm the **exact header names** used for app-to-app auth:
- Is it:
  - `X-Jarvis-App-Id`
  - `X-Jarvis-App-Key`
- Or are different names used in the actual implementation?

**Answer:** `X-Jarvis-App-Id` and `X-Jarvis-App-Key`.

3.2. Confirm whether any **additional headers** are required for app-to-app auth (for example, `X-Jarvis-Admin-Token` on admin routes).

**Answer:** Admin routes require `X-Jarvis-Admin-Token`. App-protected routes require only `X-Jarvis-App-Id` and `X-Jarvis-App-Key`.

---

## 4. Validation Logic

4.1. Describe how app credentials are validated **inside jarvis-auth**:
- Where is the validation logic located (module / function / dependency name)?
- Does it look up an `AppClient` (or similar) from the database?
- Does it compare the provided key to a stored hash using a password-hashing algorithm (e.g., bcrypt, argon2)?

**Answer:** Validation is in `jarvis_auth.app.api.dependencies.app_auth.require_app_client`. It queries `AppClient` from the DB and verifies the provided key against the stored bcrypt hash via `verify_password`.

4.2. Does the validation logic:
- Allow only **one active key per app**?
- Check an `is_active` flag or similar before accepting credentials?

**Answer:** Yes. Single key per app; it checks `is_active` before accepting.

4.3. If a service like `llm-proxy` wants to validate another app’s credentials, what is the **exact flow** right now?
- Please describe step-by-step what happens from the moment `llm-proxy` receives a request with app headers through to the final yes/no decision.

**Answer:** For a service like `llm-proxy`, the intended flow for validating another app’s credentials is:
1. `llm-proxy` receives a request from another Jarvis app containing `X-Jarvis-App-Id` and `X-Jarvis-App-Key`.
2. `llm-proxy` forwards these headers to jarvis-auth via `GET /internal/app-ping`.
3. jarvis-auth validates the credentials (DB lookup + bcrypt verify).
4. If jarvis-auth returns `200 OK`, `llm-proxy` treats the calling app as authenticated and may use the returned `app_id`/`name`.
5. If jarvis-auth returns `401`, `llm-proxy` rejects the original request.
In this model, `llm-proxy` does not maintain an allowlist or hashed keys; validation is fully delegated to jarvis-auth.

---

## 5. Admin Token and Key Management

5.1. Confirm how the **admin token** is configured and used:
- What is the exact env var name (e.g., `JARVIS_AUTH_ADMIN_TOKEN`)?
- Do all `/admin/app-clients` endpoints require this token via `X-Jarvis-Admin-Token`?

**Answer:** Env var `JARVIS_AUTH_ADMIN_TOKEN`; all `/admin/app-clients` endpoints require `X-Jarvis-Admin-Token`.

5.2. For app client **creation, rotation, and revocation**:
- Which endpoints exist, and how are they currently implemented?
- Do creation and rotation endpoints return the **raw app key once** in the response?
- Are raw keys ever stored in the database or logs, or only hashed?

**Answer:** Endpoints: create (`POST /admin/app-clients`), rotate (`POST /admin/app-clients/{app_id}/rotate`), revoke (`POST /admin/app-clients/{app_id}/revoke`), list (`GET /admin/app-clients`). Create/rotate return the raw key once. Raw keys are never stored in DB—only bcrypt hashes. Keys should not be logged.

---

## 6. Health & Internal Endpoints

6.1. Are health endpoints (e.g., `/health` or similar) **unauthenticated** as intended?
- If not, describe the current behavior.

**Answer:** Yes, `/health` is unauthenticated.

6.2. If there is an internal “ping” style endpoint used to test app auth (e.g., `/internal/app-ping`), document:
- The method and path
- Required headers
- Response format

**Answer:** `GET /internal/app-ping`; requires `X-Jarvis-App-Id`, `X-Jarvis-App-Key`; response `200 {"app_id": "<id>", "name": "<name>"}`; failures 401 with simple JSON detail messages.

---

## 7. Caching Behavior

7.1. Is there **any caching** applied to app-to-app auth decisions in `jarvis-auth`?
- For example, are valid app_id/app_key pairs cached in memory with a TTL?

**Answer:** No caching; each request performs a DB lookup and bcrypt verify.

7.2. If yes, describe where and how the cache is implemented.
- If no, confirm that each request performs a fresh validation (DB lookup + key hash check).

**Answer:** No cache; every request does a fresh DB lookup and hash check.

---

## 8. Differences from the PRDs (If Any)

8.1. Compare the current implementation to the PRDs (`app-to-app-auth.md` and `consumer-app-to-app.md`).
- Are there any **notable differences** between what was implemented and what those documents describe?
- If yes, list the differences and briefly explain why (e.g., simplified for v1, implementation constraints, etc.).

**Answer:** The core pieces match the PRDs: jarvis-auth manages app clients, stores only hashed keys, exposes admin endpoints for create/rotate/revoke/list, and provides a protected internal endpoint (`/internal/app-ping`). The main clarification is that we now **strongly prefer centralized validation** via jarvis-auth rather than consumer services maintaining local allowlists or hashes. Any previous guidance suggesting local validation should be considered superseded.

---

## 9. Summary

**Summary**
- App-to-app auth is centrally validated inside `jarvis-auth` through DB lookup + bcrypt verification.
- Consumer services (e.g., `llm-proxy`) must forward `X-Jarvis-App-Id` and `X-Jarvis-App-Key` to jarvis-auth (via `/internal/app-ping`) for validation.
- Consumer services should not store app keys or maintain local allowlists.
- Admin endpoints under `/admin/app-clients` handle create, rotate, revoke, and list operations; raw keys are returned once and only hashes are stored.
- `/health` remains unauthenticated; `/internal/app-ping` is the central validation endpoint.
- No caching is implemented; each validation call performs a DB lookup + hash check.
---

> **Reminder:** Answer everything directly in this file. Do not change other PRDs. The goal is to capture the reality of the implementation so the rest of the system (especially `llm-proxy`) can integrate correctly.