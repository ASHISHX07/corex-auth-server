
# CoreX Broker Provider Contract — V3

## 1. Purpose

Every broker integration must implement the same provider contract.

The authentication service interacts with providers through this contract and must not contain broker-specific OAuth logic.

A provider is responsible for:
- Validating broker credentials.
- Building the broker authorization URL.
- Parsing the broker callback.
- Exchanging the authorization code for a token.
- Normalizing the resulting token and optional profile.

A provider must not access D1, Express routes, client authentication, or CoreX encryption utilities.

## 2. Provider interface

Each provider exports an object with the following members:

```js
{
  id,
  credentialFields,

  validateCredentials(credentials),

  buildAuthorizationUrl({
    credentials,
    state,
    redirectUri
  }),

  parseCallback(query),

  exchange({
    code,
    credentials,
    redirectUri
  })
}
```

## 3. Contract details

### id

A stable lowercase broker identifier.

Examples:

- `upstox`
- `zerodha`
- `fyers`

It must match the identifier used by the provider registry and API request.

### credentialFields

Describes the credential fields required by the provider.

For the initial Upstox provider:

```js
["appId", "appSecret"]
```

### validateCredentials(credentials)

Validates the broker-specific credentials.

Returns:
- `null` when the credentials are valid.
- The invalid field identifier when validation fails.

Validation must not log or expose credential values.

### buildAuthorizationUrl({ credentials, state, redirectUri })

Builds the broker's authorization URL.

The provider is responsible for:
- Applying the correct broker authorization endpoint.
- Encoding broker-specific query parameters.
- Including the supplied OAuth state.
- Using the supplied redirect URI.

It must not generate or manage CoreX OAuth state itself.

Returns the complete authorization URL.

### parseCallback(query)

Parses the broker callback query parameters.

Returns either:

```js
{
  code: "authorization-code"
}
```

or:

```js
{
  error: "authorization-denied"
}
```

The provider must normalize broker-specific callback formats into this common structure.

### exchange({ code, credentials, redirectUri })

Exchanges the authorization code for a broker access token.

This operation is asynchronous.

Returns:

```js
{
  token: {
    accessToken: "token",
    tokenType: "Bearer",
    tokenExpiresAt: "2026-11-05T23:59:59.000Z"
  },
  profile: {}
}
```

`tokenExpiresAt` and `profile` are optional.

The provider must normalize its response into this structure. Broker-specific response formats must not leak into the authentication service.

## 4. Provider errors

Providers must throw a normalized `ProviderError` for expected failures.

Supported error codes:

- `authorization_denied`
- `exchange_rejected`
- `provider_unreachable`
- `provider_unavailable`
- `provider_bad_response`

Error details may be retained internally for safe diagnostics, but raw provider responses must never be returned to clients or written to request logs.

Unexpected programming errors should not be disguised as ordinary provider failures.

## 5. Responsibilities and boundaries

| Component | Responsibility |
|---|---|
| API routes | Parse HTTP requests and responses |
| Client-auth middleware | Verify client key and scope |
| Auth service | Manage sessions and lifecycle |
| Provider registry | Resolve broker identifier to provider |
| Broker provider | Handle broker-specific OAuth behavior |
| Security utilities | State sealing, token encryption and hashing |
| Database layer/services | Persist session and client data |

Providers must not:
- Query or modify D1.
- Generate client API keys.
- Encrypt or decrypt CoreX session data.
- Manage session ownership.
- Write request logs.
- Return raw broker HTTP responses to clients.

## 6. Adding a new broker

To add a broker:

1. Implement the provider contract.
2. Register the provider.
3. Add provider-specific credential validation.
4. Add authorization URL and callback handling.
5. Add token exchange and normalization.
6. Add provider tests.
7. Add end-to-end session tests.

Adding a provider must not require changes to the generic session lifecycle or token-redemption logic.

## 7. Initial implementation scope

Upstox is the first V3 provider.

Other providers should be added when their integration is ready. Do not create empty provider files or speculative abstractions for brokers that are not yet implemented.
