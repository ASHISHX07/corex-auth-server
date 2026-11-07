# CoreX Auth Server — API V3

## 1. Conventions

Base URL: the deployed CoreX Auth Server origin.

All API request and response bodies use UTF-8 JSON.

- JSON properties use camelCase.
- Timestamps use ISO 8601 UTC.
- Every response includes `X-Request-Id`.
- API responses use `Cache-Control: no-store`.
- Errors use the common error envelope, except for the defined failed-session response.
- Broker identifiers are lowercase canonical IDs.

## 2. Client authentication

Protected client endpoints require:

Authorization: Bearer cx_<43 base64url characters>

Each CoreX installation should have its own client key.

The server stores only the SHA-256 hash and the final four-character hint. Keys can be revoked independently.

The current supported scope is `auth`.

## 3. Create an authentication session

POST /api/v3/auth/sessions

Requires an active client key with the `auth` scope.

### Request

{
  "broker": "upstox",
  "credentials": {
    "appId": "BROKER-APP-ID",
    "appSecret": "BROKER-APP-SECRET"
  }
}

`credentials` is provider-specific and limited to 1 KB when serialized as JSON. Unknown credential fields are rejected.

### Success — 201 Created

{
  "sessionId": "opaque-session-id",
  "authorizationUrl": "https://broker.example/authorize",
  "sessionExpiresAt": "2026-11-07T06:00:00.000Z"
}

The caller opens `authorizationUrl` in a browser and waits for the human to complete broker authorization.

The server seals the credentials inside OAuth state. Credentials are not persisted in D1.

### Limits

- Five unfinished sessions per client.
- Ten session creations per client per minute.
- The gateway also applies its configured coarse rate limit.

Rate-limit responses include `Retry-After`.

## 4. Broker callback

GET /auth/{broker}/callback

Public endpoint called by the broker after authorization.

The callback state is authenticated and decrypted by the server, then checked against the corresponding D1 session and active client.

The callback is claimed atomically. Replaying a callback cannot exchange the authorization code twice.

The provider exchanges the authorization code and returns a normalized token/profile result. The server encrypts that result before storing it in D1.

The browser is redirected to:

GET /auth/response?broker={broker}&status={status}

This is a shared, public, static authorization-status page.

The page receives only allowlisted broker and status identifiers. It
never displays authorization codes, OAuth state, application secrets,
access tokens or session credentials.

The presentation is handled by separate static HTML, CSS and JavaScript
assets. The callback service remains independent of the page's layout.

Possible outcomes:

- received: callback processing succeeded and an encrypted result is ready
  for the CoreX client to retrieve.
- failed: broker authorization or token exchange failed.
- invalid: callback state or session could not be validated.
- expired: the authorization session expired.
- unavailable: authorization processing could not be completed because
  of a temporary service problem.

The `received` browser state does not mean the CoreX client has retrieved
the token. The client must still retrieve the authentication result through
the protected session-result endpoint.

The human-facing status page does not contain tokens or authorization codes.

## 5. Retrieve the authentication result

POST /api/v3/auth/sessions/{sessionId}/result

Requires the same active client that created the session and the `auth` scope.

The session ID alone does not grant access.

### Pending — 202 Accepted

{
  "status": "pending"
}

Response header:

Retry-After: 3

The client repeats the request after the specified interval.

### Completed — 200 OK

Delivered exactly once:

{
  "status": "completed",
  "broker": "upstox",
  "token": {
    "accessToken": "...",
    "tokenType": "Bearer",
    "tokenExpiresAt": "2026-11-07T22:00:00.000Z"
  },
  "profile": {
    "userId": "...",
    "userName": "...",
    "email": "..."
  }
}

`profile` is optional. `tokenExpiresAt` is omitted when the provider cannot determine a reliable expiry.

The provider normalizes its broker response. Clients use one token/profile shape for every broker.

After successful retrieval, the session becomes `retrieved` and the stored ciphertext is deleted.

### Failed — 409 Conflict

{
  "status": "failed",
  "error": "exchange_rejected",
  "message": "The broker rejected the token exchange."
}

A failed session remains readable until it expires.

### Other terminal responses

- 404: session not found or not owned by this client.
- 410: expired, cancelled or already retrieved.

## 6. Session lifecycle

pending -> processing -> ready -> retrieved

Terminal outcomes:

- failed
- expired
- cancelled

Session lifetime is five minutes. When a token becomes ready, the result remains available for up to 60 seconds beyond the later of the original expiry or the time the result became ready.

## 7. Public health endpoint

GET /api/health

200 OK:

{
  "status": "ok"
}

## 8. Administrator API

Administrator endpoints use a separate signed, HttpOnly, 30-minute cookie. They do not accept CoreX client keys.

| Method | Path | Purpose |
|---|---|---|
| POST | /api/v3/admin/login | Administrator login |
| POST | /api/v3/admin/logout | Clear administrator cookie |
| GET | /api/v3/admin/me | Current administrator |
| GET | /api/v3/admin/overview | Dashboard metrics |
| GET | /api/v3/admin/requests | Request metadata |
| GET | /api/v3/admin/clients | Client list |
| POST | /api/v3/admin/clients | Create client; key returned once |
| GET | /api/v3/admin/clients/{clientId} | Client details |
| PATCH | /api/v3/admin/clients/{clientId}/scopes | Update scopes |
| POST | /api/v3/admin/clients/{clientId}/revoke | Revoke client |
| GET | /api/v3/admin/sessions | Session list |
| GET | /api/v3/admin/sessions/{sessionId} | Session details |
| POST | /api/v3/admin/sessions/{sessionId}/invalidate | Cancel active session |
| GET | /api/v3/admin/audit | Audit history |

Authenticated administrator mutations require same-origin requests.

## 9. Client implementation guidance

- Cache the broker token in the CoreX instance until shortly before `tokenExpiresAt`.
- Poll using the server's `Retry-After` value.
- Back off on 429 and transient 5xx responses.
- Do not log credentials, client keys, authorization URLs, tokens or callback state.
- If the final successful response is lost after one-time retrieval, start a new login session. The server does not provide a second copy of a redeemed token.