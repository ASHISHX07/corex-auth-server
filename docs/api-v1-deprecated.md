# API v1 (deprecated)

v1 only relays the authorization code; **the client must exchange it with the broker itself**
(so the client needs a callback-less way to hold the broker secret and make that call).
It still works for existing clients, but new integrations must use v2 (see the README).
Plan: remove v1 once no client uses it (see [cleanup.md](./cleanup.md)).

### `POST /api/v1/auth/sessions`

Creates a v1 broker authorization session. Requires the **CoreX client API key** as a bearer token.

Headers:

```http
Authorization: Bearer <COREX_CLIENT_API_KEY>
Content-Type: application/json
Accept: application/json
```

Body:

```json
{
  "broker": "upstox",
  "appId": "<UPSTOX_API_KEY>"
}
```

A successful request returns `201 Created` with `sessionId`, `retrievalSecret`, `authorizationUrl`, `expiresInSeconds`, and `expiresAt`.

Common errors: `400` invalid request or unsupported broker; `401` invalid/inactive client key; `429` session rate limit; `503` authentication or rate-limiter unavailable.

## `GET /api/v1/auth/sessions/:sessionId/result`

Retrieves the authorization result. Requires the **retrieval secret from the same session**, not the CoreX client key:

```http
Authorization: Bearer <SESSION_RETRIEVAL_SECRET>
```

Expected outcomes:

- `202` with `status: "pending"`: authorization callback not received yet.
- `200` with `status: "completed"` and `authorizationCode`: code retrieved successfully.
- `410` with `status: "expired"` or an already-retrieved outcome: start a new flow if the code is no longer available.

Code retrieval is one-time. Save the code securely and exchange it promptly.


## Trying v1 with Postman

Set these Postman environment variables locally: `baseUrl`, `corexClientApiKey`, `upstoxClientId`, `upstoxClientSecret`, and `redirectUri`. Use the redirect URI shown in the Deployment section. Keep secrets out of shared workspaces and exports.

### 1. Create a session

Send `POST {{baseUrl}}/api/v1/auth/sessions` with Bearer Token `{{corexClientApiKey}}`, `Content-Type: application/json`, and body:

```json
{
  "broker": "upstox",
  "appId": "{{upstoxClientId}}"
}
```

Save `sessionId`, `retrievalSecret`, and `authorizationUrl` from the response as environment variables. Do not mix values from different sessions.

### 2. Authorize in the browser

Open the exact `authorizationUrl` returned by the request, sign in to Upstox, and complete authorization. The Upstox app's registered redirect URI must match `{{redirectUri}}` exactly. The CoreX status page should show `received` if the callback was accepted.

### 3. Retrieve the code

Send `GET {{baseUrl}}/api/v1/auth/sessions/{{sessionId}}/result` with Bearer Token `{{retrievalSecret}}`. If it returns `202 pending`, complete the browser step for that same session. On success, CoreX returns the one-time `authorizationCode`.

### 4. Exchange the code with Upstox

CoreX does not perform this exchange. Send a request directly to `POST https://api.upstox.com/v2/login/authorization/token` with `Accept: application/json`, `Content-Type: application/x-www-form-urlencoded`, and these form fields:

| Key | Value |
|---|---|
| `code` | The `authorizationCode` returned by CoreX |
| `client_id` | `{{upstoxClientId}}` |
| `client_secret` | `{{upstoxClientSecret}}` |
| `redirect_uri` | `{{redirectUri}}` |
| `grant_type` | `authorization_code` |

A successful Upstox response includes an access token. Authorization codes are single-use; if exchange fails, start a new authorization flow rather than reusing the code.

See [Upstox Authentication](https://upstox.com/developer/api-documentation/authentication/) and the [Get Token API](https://upstox.com/developer/api-documentation/get-token/).

