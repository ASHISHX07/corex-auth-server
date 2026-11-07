# API Error Catalog

## Standard error envelope

Most API errors use:

{
  "error": "invalid_request",
  "message": "The request contains invalid data.",
  "field": "credentials.appSecret"
}

`field` is optional. Messages never echo submitted values.

## Authentication API

| HTTP | Error | Meaning |
|---:|---|---|
| 400 | `invalid_request` | Invalid request or field |
| 400 | `unsupported_broker` | Broker not registered |
| 400 | `invalid_json` | Malformed JSON |
| 401 | `unauthorized` | Missing, invalid or revoked client key |
| 403 | `forbidden_scope` | Client lacks required scope |
| 404 | `session_not_found` | Unknown or foreign session |
| 409 | `authorization_denied` | Human denied broker authorization |
| 409 | `exchange_rejected` | Broker rejected code exchange |
| 409 | `provider_unreachable` | Broker could not be reached |
| 409 | `provider_unavailable` | Broker is temporarily unavailable |
| 409 | `provider_bad_response` | Broker response was invalid |
| 410 | `expired` | Session expired |
| 410 | `cancelled` | Session was cancelled |
| 410 | `already_retrieved` | Result was already redeemed |
| 413 | `payload_too_large` | Request or credentials exceed size limit |
| 415 | `unsupported_media_type` | Request body is not JSON |
| 429 | `rate_limit_exceeded` | Request rate limit reached |
| 429 | `too_many_sessions` | Five unfinished sessions already exist |
| 500 | `internal_error` | Unexpected API error |
| 503 | `authentication_unavailable` | Authentication dependency unavailable |
| 503 | `service_unavailable` | Authentication result cannot currently be served |

### Failed-session response

HTTP 409 uses:

{
  "status": "failed",
  "error": "exchange_rejected",
  "message": "The broker rejected the token exchange."
}

Other errors use the standard error envelope.

## Administrator API

Administrator errors use the same `{ error, message, field? }` envelope.

Common codes include:

- `unauthorized`
- `cross_origin`
- `invalid_request`
- `client_not_found`
- `invalid_client_id`
- `invalid_scopes`
- `session_not_found`
- `session_not_active`
- `invalid_session_filter`
- `admin_operation_failed`
- `authentication_unavailable`
- `rate_limit_exceeded`