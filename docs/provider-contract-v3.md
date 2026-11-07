# CoreX Broker Provider Contract — V3

## Purpose

A provider adapts one broker's OAuth behavior to the common CoreX authentication workflow.

Providers must not import:

- Express or HTTP route code
- D1 or other persistence code
- CoreX client authentication
- CoreX encryption or key management

The authentication service owns the session lifecycle. The provider owns broker-specific authorization, callback parsing, token exchange and normalization.

## Contract

Each registered provider exposes:

```js
{
    id,
    credentialFields,
    validateCredentials(credentials),
    buildAuthorizationUrl({ credentials, state, redirectUri }),
    parseCallback(query),
    exchange({ code, credentials, redirectUri })
}