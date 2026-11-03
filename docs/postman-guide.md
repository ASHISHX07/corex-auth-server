# End-to-end test with Postman (Upstox)

This guide runs one complete login by hand so you can see every step. Postman sends the
HTTP requests; two small Node tools (`tools/keygen.mjs`, `tools/decrypt.mjs`) do the
cryptography, because the token comes back **encrypted to a key only you hold**.

## Before you start

| You need | Where from |
|---|---|
| Node.js 18+ and this repo cloned (for `tools/`) | |
| Postman | |
| A **CoreX client API key** | Registered operators only; to get one email ashishsindhav02@outlook.com |
| Your **Upstox API key and API secret** | Upstox developer console -> your app |
| Upstox app **redirect URL** = `https://corex-server.corex-services.workers.dev/auth/upstox/callback` (exactly) | Upstox developer console -> your app |

Optional but useful: run `npx wrangler tail` in a terminal to watch requests arrive. It does not log secrets or tokens.

## Step 1: Import the collection and environment

1. Postman -> **Import** -> select both files from `docs/postman/`:
   `corex-auth-v2.postman_collection.json` and `corex-auth.postman_environment.json`.
2. **Select the environment** "CoreX Auth Server" in the dropdown at the top right of Postman.
   > If it says *No Environment*, every `{{variable}}` is sent literally and you will get a `400`
   > whose message mentions a `{{placeholder}}`. This is the most common mistake.
3. Open the environment and fill in **both the Initial and Current value columns** for:
   `corexClientApiKey`, `upstoxApiKey`, `upstoxApiSecret`. (Postman sends the *Current* value. Click **Save**.)
   Leave `clientPublicKey`, `sessionId`, `authorizationUrl`, `encryptedResult` empty for now.
4. Do not sync this environment to a shared workspace and never export it with secrets filled in.

## Step 2: Generate a keypair

From the repo root in a terminal:

```bash
node tools/keygen.mjs
```

It saves the private key to `.corex-client-key.json` (git-ignored, stays on your machine) and prints one long
line: the **public key**. Copy it into the `clientPublicKey` variable (Initial and Current) and Save.
Copy it exactly: no spaces, no line breaks.

> Make a **new** keypair for each login, and **don't run keygen again** between creating a session and decrypting
> its result. The new key would overwrite the one that session needs.

## Step 3: Health check

Send **0. Health (public)**. Expect `200 {"healthy":true,...}`. If this fails, the `baseUrl` is wrong or the Worker is down.

## Step 4: Create the session

Send **1. Create session**. It already contains:

```json
{
  "broker": "upstox",
  "appId": "{{upstoxApiKey}}",
  "appSecret": "{{upstoxApiSecret}}",
  "clientPublicKey": "{{clientPublicKey}}"
}
```

with `Content-Type: application/json` and your client key as the Bearer token.
Expect **`201`**. The collection saves `sessionId` and `authorizationUrl` into the environment and prints the URL in
the Postman Console (**View -> Show Postman Console**). You can also copy `authorizationUrl` from the environment (eye icon).

If you build the request by hand instead: Body -> **raw** -> type **JSON**, and keep that `Content-Type` header.
Sending the body as "Text" is a classic cause of a 400 ("Body must be a JSON object").

## Step 5: Log in at Upstox

Paste `authorizationUrl` into a browser **within 5 minutes**, log in to Upstox and approve.
You should land on the CoreX page **"Authorization complete"**. In `wrangler tail` you will see
`GET /auth/upstox/callback 303`.

If the page says it *couldn't verify the request*, the link was used twice, is older than 5 minutes, or is from another session. Start again from Step 4.

## Step 6: Fetch the result (one time only)

Send **2. Poll result**.

* `202` pending: the login isn't finished. Finish Step 5, send again.
* `200` completed: the body has an `encrypted` object. **This can be fetched only once.**
  The collection also stores the body in the secret variable `encryptedResult` as a safety copy.
* Anything else: see [Troubleshooting](#troubleshooting).

## Step 7: Decrypt

Copy the whole response body, then, from the repo root:

```powershell
# Windows PowerShell
Get-Clipboard | node tools/decrypt.mjs <sessionId>
```
```bash
# macOS
pbpaste | node tools/decrypt.mjs <sessionId>
# or from a file
node tools/decrypt.mjs <sessionId> response.json
```

`<sessionId>` is the value from the environment. Output:

```json
{ "accessToken": "...", "tokenType": "Bearer", "expiresAt": "2026-11-04T22:00:00.000Z",
  "profile": { "userId": "...", "userName": "..." } }
```

Upstox tokens expire at 03:30 IST the next day; `expiresAt` reflects that.

## Step 8: Prove the token works

In Postman: `GET https://api.upstox.com/v2/user/profile`, header `Accept: application/json`,
Authorization -> Bearer Token -> paste `accessToken`. A `200` with your account details means the whole chain works.

## Step 9: Check that nothing sensitive was stored

```bash
npx wrangler d1 execute corex-db --remote --command "SELECT status, failure_code, api_version, result_ciphertext, authorization_code FROM auth_sessions ORDER BY created_at DESC LIMIT 3"
```

Your row should be `retrieved`, `api_version` 2, and `NULL` in both `result_ciphertext` and `authorization_code`.
The dashboard shows the same session as **Encrypted result fetched**.

## Troubleshooting

Error bodies name the problem field but never echo what you sent.

| You see | Cause | Fix |
|---|---|---|
| `400 invalid_request`, `field: "appId"` and message mentions `{{placeholder}}` | Environment not selected, or variable empty | Select the environment (top right); fill Current values; Save |
| `400`, `field: "clientPublicKey"` | Empty, truncated, has spaces/line breaks, or not from `keygen` | Re-run `node tools/keygen.mjs`, copy the single line exactly |
| `400`, `field: "appId"` / `"appSecret"` | Missing or wrong format | Re-copy from the Upstox console |
| `400`, `field: null`, "Body must be a JSON object" | Body isn't JSON | Body -> raw -> JSON; header `Content-Type: application/json` |
| `400 unsupported_broker` | Typo in `broker` | Use a broker listed in the message (`upstox`) |
| `401 unauthorized` | Wrong/revoked CoreX client key | Check `corexClientApiKey`; ask the operator |
| `404 session_not_found` on poll | Wrong `sessionId`, or the session belongs to another client key | Use the id from Step 4 with the same key |
| `409 failed` / `authorization_denied` | You cancelled or declined at Upstox | New session |
| `409` / `exchange_rejected` | Upstox refused the exchange: wrong API secret, or the redirect URL in the Upstox app doesn't match exactly | Fix the secret / redirect URL, new session |
| `409` / `provider_unreachable`, `provider_unavailable` | Upstox unreachable or erroring | Retry later with a new session |
| `410 expired` | More than 5 min (+60 s) passed | New session |
| `410 already_retrieved` | Result already fetched | Use the saved `encryptedResult` variable; else new session |
| `429` | Rate limit (10 creates/min, 120 polls/min per client) | Wait a minute |
| `500 session_creation_failed` / `503` | Server not fully configured (e.g. `COREX_STATE_KEY` secret missing) or a dependency is down | Operator: check secrets and `wrangler tail` |
| `decrypt.mjs`: "Decryption failed" | Wrong `sessionId`, or keygen was re-run after the session was created | Start over from Step 2 |
