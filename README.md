# CoreX Auth Server V3

A Cloudflare Worker that handles Upstox OAuth for CoreX clients. It creates an authentication session, receives the broker callback, exchanges the authorization code, and returns a normalized token result to the requesting client.

**Supported broker:** Upstox.

**Production URL:** `https://corex-server-v3.corex-services.workers.dev`

## How it works

1. A CoreX client creates a session using its CoreX API key and Upstox app credentials.
2. CoreX returns an authorization URL, which the client opens in the user's browser.
3. Upstox redirects to the CoreX callback with a single-use code and sealed state.
4. CoreX validates the state and exchanges the code with Upstox.
5. CoreX encrypts the normalized token result and stores it temporarily in D1.
6. The same client retrieves the result once. CoreX then deletes the stored ciphertext.

The browser is redirected to a shared status page. It displays the callback outcome only; it never displays credentials, authorization codes or tokens.

## Client API

Protected endpoints require:

```http
Authorization: Bearer <COREX_CLIENT_API_KEY>
```

Each client has its own key. CoreX stores only its SHA-256 hash. The required scope is `auth`. API responses include `X-Request-Id` and `Cache-Control: no-store`.

### Create a session

`POST /api/v3/auth/sessions`

```json
{
  "broker": "upstox",
  "credentials": {
    "appId": "<UPSTOX_API_KEY>",
    "appSecret": "<UPSTOX_API_SECRET>"
  }
}
```

`201 Created`:

```json
{
  "sessionId": "<SESSION_ID>",
  "authorizationUrl": "https://api.upstox.com/v2/login/authorization/dialog?...",
  "sessionExpiresAt": "<ISO-8601-UTC>"
}
```

Open `authorizationUrl` in the user's browser. Treat it as sensitive because it contains sealed OAuth state. The initial session lifetime is five minutes. Credentials are limited to 1 KB and undeclared fields are rejected.

### Broker callback

`GET /auth/upstox/callback`

Upstox calls this public, rate-limited endpoint through the user's browser redirect. Clients must not call it directly. The callback is validated using sealed state and can be claimed only once.

The browser is redirected to `/auth/response?broker=upstox&status=<status>`. Supported statuses are `received`, `failed`, `invalid`, `expired` and `unavailable`. `received` means the encrypted result is ready for retrieval; it does not mean the client has retrieved it.

### Retrieve the result

`POST /api/v3/auth/sessions/<sessionId>/result`

Use the same client API key that created the session. No request body is required.

`202 Accepted` while processing:

```json
{ "status": "pending" }
```

The response includes `Retry-After: 3`.

`200 OK` when ready:

```json
{
  "status": "completed",
  "broker": "upstox",
  "token": {
    "accessToken": "<ACCESS_TOKEN>",
    "tokenType": "Bearer",
    "tokenExpiresAt": "<ISO-8601-UTC>"
  },
  "profile": {
    "userId": "<USER_ID>",
    "userName": "<USER_NAME>",
    "email": "<EMAIL>"
  }
}
```

`profile` and `tokenExpiresAt` are optional when reliable values are unavailable. CoreX returns this normalized shape, not the broker's raw response. Retrieval is one-time; a repeat returns `410 already_retrieved`.

### Public endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET` | `/auth/response` | Browser authorization status page |

## Errors

Standard error body:

```json
{
  "error": "invalid_request",
  "message": "The request contains invalid data.",
  "field": "credentials.appSecret"
}
```

`field` is optional. Failed-session retrieval uses `status`, `error` and `message`.

| HTTP | Error | Meaning |
|---:|---|---|
| 400 | `invalid_request` | Invalid request or credential field |
| 400 | `unsupported_broker` | Broker is not supported |
| 401 | `unauthorized` | Missing, invalid or revoked client key |
| 403 | `forbidden_scope` | Client lacks `auth` scope |
| 404 | `session_not_found` | Session missing or belongs to another client |
| 409 | `authorization_denied` | User denied authorization |
| 409 | `exchange_rejected` | Upstox rejected the code exchange |
| 409 | `provider_unreachable` | Outbound request failed before a usable response |
| 409 | `provider_unavailable` | Upstox returned a temporary server/rate-limit response |
| 409 | `provider_bad_response` | Upstox returned an invalid or unexpected response |
| 410 | `expired`, `cancelled`, `already_retrieved` | Session is no longer retrievable |
| 413 | `payload_too_large` | Credentials exceed the size limit |
| 415 | `unsupported_media_type` | Request body is not JSON |
| 429 | `rate_limit_exceeded`, `too_many_sessions` | Request or session limit reached |
| 503 | `authentication_unavailable`, `service_unavailable` | Required service operation is unavailable |

Honor `Retry-After`. Authorization codes are single-use; start a new session after a failed exchange rather than retrying the same code.

## Administrator console

Open `/login.html` on the Worker. Administrator authentication is separate from client API-key authentication. The console supports request and session monitoring, client creation and revocation, session invalidation, overview metrics and audit history. There is no public client-registration endpoint; an administrator creates client keys, which are shown once.

Admin API (`/api/v3/admin`):

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/login`, `/logout` | Sign in and out |
| `GET` | `/me`, `/overview`, `/requests`, `/clients`, `/sessions`, `/audit` | Read admin data |
| `POST` | `/clients` | Create a client |
| `GET` | `/clients/:clientId`, `/sessions/:sessionId` | Inspect a client or session |
| `PATCH` | `/clients/:clientId/scopes` | Update client scopes |
| `POST` | `/clients/:clientId/revoke` | Revoke a client |
| `POST` | `/sessions/:sessionId/invalidate` | Cancel an active session |

## Security and operations

- OAuth state and temporary token results use AES-GCM with purpose-derived keys.
- Broker app credentials are not stored as plaintext in D1. Authorization codes are exchanged in memory and are not stored.
- Token ciphertext is deleted after successful one-time retrieval.
- Client keys are stored as SHA-256 hashes. Admin passwords use PBKDF2-HMAC-SHA-256; admin sessions use a signed, `HttpOnly`, `SameSite=Strict` cookie with a 30-minute lifetime.
- Request logs contain metadata only, never request bodies, query strings, credentials, OAuth state or tokens.
- Limits: five unfinished sessions per client and ten session creations per minute. Polling and callbacks are rate-limited.
- A one-minute Cron Trigger expires sessions and removes old data. Retention: request logs 30 days, terminal sessions 90 days, audit records 365 days.

The Worker operator is trusted: broker credentials and access tokens necessarily exist in Worker memory while processing the exchange and result retrieval.