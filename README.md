# CoreX Auth Server V3

A Cloudflare Worker that handles broker OAuth for CoreX clients. The server performs the authorization-code exchange and delivers a normalized token result to the client.

**Supported broker:** Upstox  
**Production:** https://corex-server-v3.corex-services.workers.dev  
**Admin console:** https://corex-server-v3.corex-services.workers.dev/login.html

## OAuth flow

1. A CoreX client creates an authentication session using its API key and Upstox app credentials.
2. The client opens the returned authorization URL in the user's browser.
3. Upstox redirects to the CoreX callback.
4. CoreX validates the sealed OAuth state and exchanges the authorization code server-side.
5. The normalized token result is encrypted in D1 until the same client retrieves it once.
6. The stored ciphertext is deleted after successful retrieval.

The browser is redirected to a public status page. It shows the outcome only; it never displays credentials, authorization codes or tokens.

## Client API

Protected requests use the client key:

```http
Authorization: Bearer <COREX_CLIENT_API_KEY>
```

### Create a session

`POST /api/v3/auth/sessions`

```json
{
  "broker": "upstox",
  "credentials": {
    "appId": "<UPSTOX_APP_ID>",
    "appSecret": "<UPSTOX_APP_SECRET>"
  }
}
```

The `201 Created` response contains `sessionId`, `authorizationUrl` and `sessionExpiresAt`. Open the authorization URL in the user's browser.

### Callback

`GET /auth/upstox/callback`

Register this exact callback URL in the Upstox developer application:

`https://corex-server-v3.corex-services.workers.dev/auth/upstox/callback`

### Retrieve the result

`POST /api/v3/auth/sessions/{sessionId}/result`

Use the same client key that created the session. The endpoint returns `202 pending` while the exchange is processing, then `200 completed` with the normalized token and optional profile. Retrieval is one-time; subsequent retrieval attempts are rejected.

### Public endpoints

- `GET /api/health` — health check.
- `GET /auth/response` — browser-facing authorization status page.

## Admin console

Open `/login.html` on the production Worker. Administrators can create and revoke CoreX clients, inspect sessions and request metadata, invalidate active sessions, and view audit history. Client keys are shown only once when created.

## Security and limits

- Client API keys are stored as SHA-256 hashes; each client has its own key.
- OAuth state and temporary token results use AES-GCM with purpose-derived keys.
- Broker app credentials are sealed into OAuth state and are not stored in plaintext in D1.
- Token results are encrypted at rest and deleted after one-time retrieval.
- Administrator authentication is separate from client authentication and uses salted PBKDF2-HMAC-SHA-256 password hashes with signed, HttpOnly session cookies.
- Request logs contain metadata only, not request bodies, credentials, OAuth state or tokens.
- Sessions expire after five minutes. A client may have up to five unfinished sessions and create up to ten sessions per minute.
- A one-minute scheduled task expires sessions and applies data-retention cleanup.

The Worker operator is trusted: broker credentials and access tokens necessarily exist in Worker memory while processing authorization.

## Documentation

- [V3 API reference](docs/api-v3.md)
- [Error reference](docs/error.md)
- [Broker provider contract](docs/provider-contract-v3.md)

## Development

Requires Node.js 22.5 or later.

```powershell
npm ci
npm test
```
