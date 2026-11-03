# Adding a broker

Routes, callback handling, the database, logging and the status page are all broker-agnostic.
A new broker is **one file plus one line**:

1. Create `server/providers/<broker>-provider.js` exporting `create<Broker>Provider(env)`
   that returns the contract below (see `upstox-provider.js` for a complete example):

   ```js
   {
     name: "zerodha",                    // lower-case id; also the URL segment
     callbackPath: "/auth/zerodha/callback",
     validateCredentials({ appId, appSecret }) -> null | "appId" | "appSecret"  // name of the bad field, never its value
     buildAuthorizationUrl({ appId, state })   -> string,
     async exchangeCode({ code, appId, appSecret })
         -> { accessToken, tokenType, expiresAt /* ISO string */, profile /* whitelisted */ }
         // throw new ProviderError("some_code") on failure; never include upstream bodies
   }
   ```
2. Register it in `server/providers/provider-registry.js`.
3. Add `<BROKER>_REDIRECT_URI` to `wrangler.jsonc` `vars` and register the same URL in the
   broker's developer console (`https://<worker>/auth/<broker>/callback`).

No migration is needed (the `broker` column is free text). Optionally add a label/mark for
the status page in `public/auth-response.js` (unknown brokers get an automatic fallback).

Brokers whose flow differs (checksum-based exchange like Kite's `SHA256(api_key + request_token + secret)`,
different callback parameter names such as `request_token`, or PKCE) fit the same contract:
`exchangeCode` receives `code` from the callback and can compute whatever the broker needs.
If a broker uses a callback parameter other than `code`, map it in `broker-callback.routes.js`.
