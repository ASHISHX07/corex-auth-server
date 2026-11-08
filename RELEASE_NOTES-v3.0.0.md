# CoreX Auth Server V3

Production release of the CoreX broker-authentication service.

## Highlights

- Server-side Upstox OAuth authorization-code exchange.
- Sealed OAuth state and purpose-derived AES-GCM encryption.
- Normalized token and profile delivery through a one-time client retrieval endpoint.
- Protected administrator console for client management, session monitoring, and audit history.
- Rate-limited authentication endpoints and metadata-only request logging.
- Scheduled session expiry and data-retention cleanup.
- Shared browser authorization-status page.

## Compatibility

This release uses the V3 client API under `/api/v3`. CoreX installations must use a V3-issued client API key and the V3 session/result flow. Upstox is the currently supported broker.

See the [README](https://github.com/ASHISHX07/corex-auth-server/blob/v3/README.md) and the [V3 API reference](https://github.com/ASHISHX07/corex-auth-server/blob/v3/docs/api-v3.md) for integration details.
