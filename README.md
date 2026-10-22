# CoreX Auth Server

CoreX Auth Server is a Cloudflare Workers service that helps registered CoreX clients complete an Upstox OAuth authorization flow. It creates a short-lived session, sends the user to Upstox, receives the callback, and lets the client retrieve the one-time authorization code. A protected Admin Console shows clients, OAuth sessions, and recorded API requests.

> **Current scope:** Upstox is the only implemented broker. CoreX returns the authorization code; the integrating client exchanges it with Upstox for an access token.

## Deployment

| Setting | Current value |
|---|---|
| Cloudflare Worker | `corex-server` |
| Production URL | `https://corex-server.corex-services.workers.dev` |
| Health check | `/api/health` |
| Upstox callback | `https://corex-server.corex-services.workers.dev/auth/upstox/callback` |
| Database | Cloudflare D1, `corex-db` |
| Web assets | `public/` |

These values match the current `wrangler.jsonc`. If the Worker domain or name changes, update the Upstox Developer App's redirect URI and the configured `UPSTOX_REDIRECT_URI` to match exactly.

## How it works

1. A registered CoreX client creates a session using its CoreX API key.
2. CoreX returns a session ID, a private retrieval secret, and an Upstox authorization URL.
3. The user opens that URL and signs in to Upstox.
4. Upstox redirects to CoreX. CoreX validates the returned `state` and records the authorization code.
5. The client retrieves the code once using the session ID and that session's retrieval secret.
6. The client exchanges the code directly with Upstox for a token.

Sessions expire after **five minutes**. Always use the `authorizationUrl`, `sessionId`, and `retrievalSecret` from the same create-session response. Polling the result endpoint does not complete browser authorization.

## Broker support

- **Upstox:** implemented.
- **FYERS and Zerodha:** not connected to provider implementations yet.
- **Angel One:** not implemented.

Names shown in UI labels do not imply a working integration.

## API reference

All paths are relative to the production base URL above.

### `GET /api/health`

Public health check. Returns `healthy: true` and a timestamp.

### `POST /api/v1/auth/sessions`

Creates a broker authorization session. Requires the **CoreX client API key** as a bearer token.

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

### `GET /api/v1/auth/sessions/:sessionId/result`

Retrieves the authorization result. Requires the **retrieval secret from the same session**, not the CoreX client key:

```http
Authorization: Bearer <SESSION_RETRIEVAL_SECRET>
```

Expected outcomes:

- `202` with `status: "pending"`: authorization callback not received yet.
- `200` with `status: "completed"` and `authorizationCode`: code retrieved successfully.
- `410` with `status: "expired"` or an already-retrieved outcome: start a new flow if the code is no longer available.

Code retrieval is one-time. Save the code securely and exchange it promptly.

### Browser callback and status page

- `GET /auth/upstox/callback` — configured as the Upstox redirect URI. Receives the broker callback; users should not call this manually.
- `GET /auth/response` — displays a safe authorization status page. A `received` status confirms that CoreX accepted the callback; it does not prove that a token was issued.

### Admin API

All `/api/v1/admin/*` routes require an authenticated admin session cookie or the configured admin bearer key.

| Method and path | Purpose |
|---|---|
| `POST /api/v1/admin/login` | Sign in and establish the dashboard session cookie. |
| `POST /api/v1/admin/logout` | End the browser session. |
| `GET /api/v1/admin/me` | Get the current admin identity. |
| `GET /api/v1/admin/overview?period=24h` | Dashboard metrics; periods are `24h`, `7d`, or `30d`. |
| `GET /api/v1/admin/requests?limit=25&period=24h&cursor=...` | Paginated request logs. Limits are capped at 100. |
| `GET /api/v1/admin/clients?q=...&limit=50` | List or search registered clients. |
| `GET /api/v1/admin/clients/:clientId` | Inspect a client and related sessions. |
| `POST /api/v1/admin/clients/:clientId/revoke` | Revoke a client and expire its open sessions. |
| `GET /api/v1/admin/sessions?limit=50&status=...&broker=...` | List and filter OAuth sessions. |
| `GET /api/v1/admin/sessions/:sessionId` | Inspect a session. |
| `POST /api/v1/admin/sessions/:sessionId/invalidate` | Invalidate an open session. |

There is no public client-registration endpoint in this repository; active client credentials must be provisioned through a trusted operator process.

## Try the Upstox flow with Postman

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

## Admin Console

The browser dashboard is served by the same Worker. Unauthenticated visitors to `/` are redirected to `/login.html`.

- Admin passwords are verified against PBKDF2-HMAC-SHA-256 hashes with per-user salts.
- Login issues a signed session cookie with a 30-minute lifetime. The cookie is `HttpOnly` and `SameSite=Strict`; production HTTPS requests use `Secure`.
- Login, logout, and cookie-authenticated state-changing admin requests enforce same-origin checks.
- Admin pages send security headers, including a Content Security Policy and `Referrer-Policy: no-referrer`.
- An optional `COREX_ADMIN_API_KEY` supports trusted admin API access. Treat it as a high-privilege secret.

The dashboard supports request-period filters, cursor-based pagination, and CSV export. The session list's **Retrieved** status means the authorization code was retrieved—not that the client exchanged it for an access token.

## Request logging and data

Cloudflare D1 stores:

- `corex_clients` — registered CoreX clients and hashed API keys.
- `auth_sessions` — OAuth session status and lifecycle timestamps.
- `request_logs` — method, path, HTTP status, duration, and optional client/broker information.

The request logger records `/api/*` requests except `/api/v1/admin/*`, plus `/auth/upstox/callback`. Static assets and admin-dashboard API calls are intentionally excluded. Metrics cover records actually written to D1; previous traffic is not backfilled. Logging is best-effort, so an application request can succeed even if its log insert fails.

## Configuration and local development

Requirements: Node.js, npm, a Cloudflare account for remote deployment, and an Upstox Developer App for live authorization.

1. Install dependencies:

   ```bash
   npm install
   ```

2. Set up local admin accounts and secrets:

   ```bash
   node scripts/setup-admin-users.cjs
   ```

   The script creates two distinct admin accounts and writes local settings to `.dev.vars`. Keep that file private; it is ignored by Git.

3. Apply migrations to the **local** D1 database and start the Worker:

   ```bash
   npx wrangler d1 migrations apply corex-db --local
   npm run dev
   ```

   Local D1 data is separate from production D1. Migrations create tables but do not copy production data. An active CoreX client must exist in the target database to create OAuth sessions.

### Production setup and deployment

Configure the required Worker secrets `COREX_ADMIN_USERS` and `COREX_ADMIN_SESSION_SECRET`. Configure `COREX_ADMIN_API_KEY` only if bearer-based admin API access is needed. Set `UPSTOX_REDIRECT_URI` to the exact callback URL registered in Upstox. Keep secrets out of source control.

Review migrations before applying them to the remote database, then deploy the intended commit:

```bash
npx wrangler d1 migrations apply corex-db --remote
npm run deploy
```

Do not deploy an untested working tree. After deployment, verify admin login, `GET /api/health`, one complete Upstox flow, and the dashboard's client, session, and request panels.

## Security notes and limitations

- Never expose CoreX client keys, admin credentials, Upstox secrets, retrieval secrets, authorization codes, or access tokens.
- Only the Upstox OAuth flow is implemented at this revision; no token storage or refresh-token management is provided.
- Client provisioning is an operator task; there is no client-creation API in this repository.
- Session creation is rate-limited per client; Upstox callbacks and admin login have separate configured rate limits in `wrangler.jsonc`.
- Request-log retention, backups, and operational monitoring should be decided before running the service at larger scale.
- This README describes the current implementation; it is not a claim of formal security certification or audit.

## License

No license file is currently present in this repository. Add a `LICENSE` before publishing if you intend to grant others permission to use, modify, or redistribute the project.
