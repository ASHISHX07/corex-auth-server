# Client integration (API v2)

The CoreX server now does the whole OAuth flow, including the token exchange. Your
instance only needs an outbound HTTPS connection: no local port, no callback listener.

## Why a keypair?

The server never stores the access token in readable form. Before the login starts your
instance generates an **ECDH P-256 keypair** and sends the *public* key. When the broker
redirects back, the server exchanges the code, **encrypts the token to your public key**,
and keeps only that ciphertext for a few minutes (until you fetch it once). Only your
private key can decrypt it. Keep the private key in memory for the duration of the login.

## Flow

1. Generate an ECDH P-256 keypair (`node tools/keygen.mjs` does this for manual testing). Export the public key as the **raw uncompressed point**
   (65 bytes, starts with `0x04`), base64url-encoded.
2. `POST /api/v2/auth/sessions` with `Authorization: Bearer <COREX_CLIENT_API_KEY>`:
   ```json
   { "broker": "upstox", "appId": "<API_KEY>", "appSecret": "<API_SECRET>", "clientPublicKey": "<b64url>" }
   ```
   -> `201 { sessionId, authorizationUrl, expiresInSeconds, expiresAt }`.
   The broker secret is sealed into the OAuth `state` and is never written to the database.
3. Open `authorizationUrl` in the user's browser. The user logs in at the broker.
4. Poll `GET /api/v2/auth/sessions/:sessionId/result` (same bearer key) every ~2 s:
   - `202 {status:"pending"}`: keep polling
   - `200 {status:"completed", encrypted:{...}}`: decrypt (below). Retrievable **once**.
   - `409 {status:"failed", error}`: e.g. `authorization_denied`, `exchange_rejected`
   - `410`: `expired` or `already_retrieved`; start a new session
   - `404`: unknown session (or not yours)
5. Decrypt `encrypted` to get `{ accessToken, tokenType, expiresAt, profile }`.

## Envelope format

`encrypted = { v:2, alg, epk, iv, ct }` (all base64url):

- shared = ECDH(clientPrivateKey, `epk`), 32 bytes
- key = HKDF-SHA256(shared, salt = UTF-8 `sessionId`, info = UTF-8 `corex-token-v2`) -> 32 bytes
- plaintext = AES-256-GCM-decrypt(key, iv = `iv`, aad = UTF-8 `sessionId`, `ct` with the 16-byte tag appended)
- plaintext is UTF-8 JSON

Any language works (Rust: `p256`, `hkdf`, `aes-gcm`; Python: `cryptography`; Go: `crypto/ecdh`).
A complete Node reference is in [`client-example.mjs`](./client-example.mjs).

## Notes

- Sessions live 5 minutes. After the token is ready you have a further 60 s to fetch it.
- Upstox access tokens expire daily at 03:30 IST; `expiresAt` reflects this. There is no
  refresh token, so run the login again.
- The Upstox app's registered redirect URI stays `https://<worker>/auth/upstox/callback`.
- API v1 keeps working (deprecated). It still returns the raw authorization code.
