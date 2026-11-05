
# CoreX Auth API v3

**Status:** Implementation contract  
**API prefix:** `/api/v3`  
**Authentication:** CoreX client API key  
**Content type:** `application/json`

## 1. Purpose

CoreX Auth Server provides a secure authentication handoff between client applications and supported brokers.

The client application initiates an authentication session, the user authorizes access through the broker, and CoreX securely exchanges and temporarily stores the resulting token.

The client retrieves the result through an authenticated, ownership-checked, one-time operation.

CoreX is an authentication control plane. It does not handle trading orders, market data, or portfolio operations.

## 2. General conventions

- All API request and response bodies use JSON.
- JSON property names use camelCase.
- Timestamps use ISO 8601 UTC.
- Deployed API communication requires HTTPS.
- API responses include `X-Request-Id`.
- API responses use `Cache-Control: no-store`.
- Unknown `/api` routes return JSON errors.
- Malformed JSON returns a standardized JSON error.
- Secrets, access tokens, authorization codes and OAuth state values must never appear in application logs.

### Client authentication

Protected endpoints require:

`Authorization: Bearer <client-api-key>`

Client keys use the `cx_` prefix followed by 43 base64url characters.

Only the SHA-256 hash and a short display hint are stored in D1. The original key is shown only when it is created.

### Scopes

The `auth` scope is required for authentication-session operations.

Clients without the required scope receive `403 forbidden_scope`.

## 3. Endpoints

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| POST | `/api/v3/auth/sessions` | Client key (`auth`) | Create an authentication session |
| POST | `/api/v3/auth/sessions/:sessionId/result` | Client key (`auth`) | Retrieve the authentication result |
| GET | `/auth/:broker/callback` | Public, sealed OAuth state | Broker OAuth callback |
| GET | `/auth/response` | Public | Browser-facing authentication result page |
| GET | `/api/health` | Public | Health check |

## 4. Create an authentication session

`POST /api/v3/auth/sessions`

Requires the `auth` scope.

### Request

```json
{
  "broker": "upstox",
  "credentials": {
    "appId": "your-app-id",
    "appSecret": "your-app-secret"
  }
}
```

The credentials object must not exceed 1 KB.

The broker must be registered and enabled. Each provider validates its own required credential fields.

### Success response

HTTP `201 Created`

```json
{
  "sessionId": "opaque-session-id",
  "authorizationUrl": "https://broker.example.com/authorize?...",
  "sessionExpiresAt": "2026-11-05T12:05:00.000Z"
}
```

The client opens `authorizationUrl` in a browser or system authentication window.

The session ID must be treated as an opaque identifier. It is not a replacement for client authentication.

## 5. Retrieve an authentication result

`POST /api/v3/auth/sessions/:sessionId/result`

Requires the `auth` scope and the same owning client that created the session.

No request body is required.

### Pending session

HTTP `202 Accepted`

Header:

`Retry-After: 3`

```json
{
  "status": "pending"
}
```

The client should wait and poll again according to the retry interval.

### Completed session

HTTP `200 OK`

```json
{
  "status": "completed",
  "broker": "upstox",
  "token": {
    "accessToken": "broker-access-token",
    "tokenType": "Bearer",
    "tokenExpiresAt": "2026-11-05T23:59:59.000Z"
  },
  "profile": {}
}
```

`tokenExpiresAt` and `profile` are optional when the provider does not supply them.

The token is returned as ordinary JSON over HTTPS, after client authentication and session ownership verification.

### One-time retrieval

A completed result can be retrieved only once.

Retrieval must atomically:
1. Verify that the session is owned by the requesting client.
2. Verify that the session is ready for retrieval.
3. Decrypt the stored token.
4. Return the result.
5. Mark the session as retrieved.
6. Delete the stored ciphertext.

Concurrent requests must not be able to retrieve the same token more than once.

## 6. OAuth callback

`GET /auth/:broker/callback`

This endpoint is public because the broker redirects the user's browser to it.

The callback must validate the sealed OAuth state before processing the authorization result.

The state must be bound to:
- Session ID
- Client ID
- Broker
- Expiration time

Callback processing must be protected against replay.

The callback must never expose access tokens, app secrets, authorization codes or encrypted payloads in browser responses.

After processing, redirect or display the appropriate browser-facing status through `/auth/response`.

## 7. Session lifecycle

```text
pending
   |
   v
processing
   |
   v
ready
   |
   v
retrieved
```

Terminal outcomes:

- `failed`
- `cancelled`
- `expired`

### State definitions

| State | Meaning |
|---|---|
| pending | Session created; waiting for broker authorization |
| processing | Callback accepted; authorization code is being exchanged |
| ready | Token successfully exchanged and encrypted for retrieval |
| retrieved | Client successfully retrieved the token |
| failed | Authentication or provider exchange failed |
| cancelled | User denied or cancelled authorization |
| expired | Session or retrieval window expired |

### Expiration

- A session has a lifetime of 5 minutes from creation.
- A session that does not complete authorization before expiration becomes expired.
- A successfully completed result remains retrievable for up to 60 seconds after the session expiration time.
- After that grace period, the result must be expired and its ciphertext removed.

The cleanup process must also remove ciphertext belonging to expired, failed or otherwise unretrievable sessions.

## 8. Standard error format

All API errors use this structure:

```json
{
  "error": "invalid_request",
  "message": "The request is invalid.",
  "field": "credentials.appSecret"
}
```

`field` is optional.

Error responses must never echo secret values, authorization codes, tokens, provider response bodies or other sensitive input.

### Error catalog

| HTTP | Error code | Meaning |
|---|---|---|
| 400 | `invalid_request` | Request validation failed |
| 400 | `invalid_json` | Malformed JSON |
| 400 | `unsupported_broker` | Broker is not supported |
| 401 | `unauthorized` | Missing or invalid client key |
| 403 | `forbidden_scope` | Client lacks the required scope |
| 404 | `session_not_found` | Session does not exist or is not owned by the client |
| 404 | `not_found` | Unknown API route |
| 409 | `authorization_denied` | User denied authorization |
| 409 | `exchange_rejected` | Broker rejected token exchange |
| 409 | `provider_unreachable` | Provider could not be reached |
| 409 | `provider_unavailable` | Provider is temporarily unavailable |
| 409 | `provider_bad_response` | Provider returned an invalid response |
| 410 | `expired` | Session or result expired |
| 410 | `cancelled` | Session was cancelled |
| 410 | `already_retrieved` | Result was already retrieved |
| 413 | `payload_too_large` | Request exceeds allowed size |
| 415 | `unsupported_media_type` | Request is not JSON |
| 429 | `rate_limit_exceeded` | Rate limit exceeded |
| 429 | `too_many_sessions` | Client exceeded its active-session limit |
| 500 | `internal_error` | Unexpected internal error |
| 503 | `service_unavailable` | Service temporarily unavailable |

Unknown session IDs and sessions belonging to another client must produce the same `404` response.

## 9. Security requirements

### Client credentials

- Generate cryptographically random client keys.
- Store only SHA-256 hashes and display hints.
- Verify the required scope on protected endpoints.
- Verify ownership for every session operation.
- Support revocation.

### OAuth state

- Seal OAuth state using AES-256-GCM.
- Derive the state-encryption key from `COREX_MASTER_KEY` using HKDF-SHA256 and the context `corex/state/v3`.
- Enforce expiration and callback replay protection.

### Token storage

- Encrypt broker tokens at rest using AES-256-GCM.
- Derive the token-encryption key using HKDF-SHA256 and the context `corex/token/v3`.
- Bind ciphertext to its session and broker using authenticated additional data.
- Delete ciphertext immediately after successful one-time retrieval.
- Never store plaintext broker tokens in D1.

### Logging

Request logs must contain metadata only.

Never log:
- App secrets
- Client API keys
- Authorization codes
- OAuth state
- Access or refresh tokens
- Token ciphertext
- Full sensitive provider responses

## 10. API versioning and compatibility

V3 uses `/api/v3`.

V1 and V2 remain operational until the V3 deployment has been verified and the migration/cutover plan is complete.

V3 implementation must not silently change V1 or V2 behavior.

Legacy database columns and functionality remain until the explicit retirement stage.
