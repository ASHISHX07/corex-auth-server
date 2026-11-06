import { getProvider } from "../../brokers/registry.js";
import { getBrokerRedirectUri } from "../../gateway/config.js";
import { randomBase64Url } from "../../security/encoding.js";
import { ProviderError } from "../../brokers/provider-error.js";

import {
    openOAuthState,
    sealOAuthState,
    sealTokenResult,
    openTokenResult
} from "../../security/seal.js";

const SESSION_TTL_SECONDS = 300;
const MAX_UNFINISHED_SESSIONS = 5;
const MAX_CREATIONS_PER_MINUTE = 10;
const MAX_CREDENTIAL_BYTES = 1024;

const encoder = new TextEncoder();

function isRecord(value) {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}

function failure(error, httpStatus, field, retryAfter) {
    return {
        error,
        httpStatus,
        ...(field && { field }),
        ...(retryAfter && { retryAfter })
    };
}

function validateCredentials(provider, credentials) {
    if (!isRecord(credentials)) {
        return failure("invalid_request", 400, "credentials");
    }

    const serialized = JSON.stringify(credentials);

    if (
        encoder.encode(serialized).byteLength >
        MAX_CREDENTIAL_BYTES
    ) {
        return failure("payload_too_large", 413);
    }

    const fields = provider.credentialFields;

    if (
        !Array.isArray(fields) ||
        !fields.includes("appId") ||
        new Set(fields).size !== fields.length
    ) {
        throw new Error("Invalid broker provider contract.");
    }

    // Only credentials explicitly declared by the provider are accepted.
    const unknownField = Object.keys(credentials).find(
        field => !fields.includes(field)
    );

    if (unknownField) {
        return failure(
            "invalid_request",
            400,
            `credentials.${unknownField}`
        );
    }

    const normalized = Object.fromEntries(
        fields
            .filter(field => Object.hasOwn(credentials, field))
            .map(field => [field, credentials[field]])
    );

    const invalidField = provider.validateCredentials(normalized);

    if (invalidField) {
        const field = invalidField === "credentials"
            ? "credentials"
            : fields.includes(invalidField)
                ? `credentials.${invalidField}`
                : "credentials";

        return failure("invalid_request", 400, field);
    }

    // Every provider exposes its public application identifier as appId.
    // The provider maps this normalized name to its broker-specific field.
    if (
        typeof normalized.appId !== "string" ||
        !normalized.appId.trim()
    ) {
        return failure(
            "invalid_request",
            400,
            "credentials.appId"
        );
    }

    return { credentials: normalized };
}

async function getSessionCreationLimits(env, clientId, now) {
    return env.DB.prepare(`
        SELECT
            c.status,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
                  AND s.status IN ('pending', 'processing', 'ready')
                  AND s.expires_at > ?
            ) AS unfinished_count,

            (
                SELECT COUNT(*)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
                  AND s.created_at > ?
            ) AS recent_count,

            (
                SELECT MIN(s.created_at)
                FROM auth_sessions s
                WHERE s.corex_client_id = c.corex_client_id
                  AND s.api_version = 3
                  AND s.created_at > ?
            ) AS oldest_recent_creation

        FROM corex_clients c
        WHERE c.corex_client_id = ?
    `).bind(
        now,
        now - 60,
        now - 60,
        clientId
    ).first();
}

export async function createAuthSession(env, {
    clientId,
    body
}) {
    if (!env?.DB) {
        throw new Error("Database binding is missing.");
    }

    if (!isRecord(body)) {
        return failure("invalid_request", 400);
    }

    if (
        typeof body.broker !== "string" ||
        !body.broker.trim()
    ) {
        return failure("invalid_request", 400, "broker");
    }

    const broker = body.broker.trim().toLowerCase();

    if (!/^[a-z0-9_-]{2,32}$/.test(broker)) {
        return failure("invalid_request", 400, "broker");
    }

    const provider = getProvider(broker);

    if (!provider) {
        return failure("unsupported_broker", 400);
    }

    const credentialResult = validateCredentials(
        provider,
        body.credentials
    );

    if (credentialResult.error) {
        return credentialResult;
    }

    const credentials = credentialResult.credentials;

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + SESSION_TTL_SECONDS;

    // 128 bits of cryptographically random session ID.
    const sessionId = randomBase64Url(16);

    const redirectUri = getBrokerRedirectUri(env, broker);

    // Credentials are encrypted into OAuth state, never inserted into D1.
    const state = await sealOAuthState(env, {
        sessionId,
        clientId,
        broker,
        expiresAt,
        credentials
    });

    const authorizationUrl = provider.buildAuthorizationUrl({
        credentials,
        state,
        redirectUri
    });

    // Only allow HTTPS authorization URLs from trusted providers.
    if (new URL(authorizationUrl).protocol !== "https:") {
        throw new Error("Provider returned an invalid authorization URL.");
    }

    // One conditional INSERT enforces the client status, unfinished-session
    // limit and creation rate limit atomically.
    const insert = await env.DB.prepare(`
        INSERT INTO auth_sessions (
            session_id,
            corex_client_id,
            broker,
            provider_app_id,
            api_version,
            status,
            created_at,
            expires_at
        )
        SELECT
            ?,
            ?,
            ?,
            ?,
            3,
            'pending',
            ?,
            ?
        WHERE EXISTS (
            SELECT 1
            FROM corex_clients
            WHERE corex_client_id = ?
              AND status = 'active'
        )
        AND (
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE corex_client_id = ?
              AND api_version = 3
              AND status IN ('pending', 'processing', 'ready')
              AND expires_at > ?
        ) < ?
        AND (
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE corex_client_id = ?
              AND api_version = 3
              AND created_at > ?
        ) < ?
    `).bind(
        sessionId,
        clientId,
        broker,
        credentials.appId,
        now,
        expiresAt,
        clientId,
        clientId,
        now,
        MAX_UNFINISHED_SESSIONS,
        clientId,
        now - 60,
        MAX_CREATIONS_PER_MINUTE
    ).run();

    if (!insert.success) {
        throw new Error("Authentication session creation failed.");
    }

    if (insert.meta?.changes !== 1) {
        // Determine why the conditional insert was rejected.
        const limits = await getSessionCreationLimits(
            env,
            clientId,
            now
        );

        if (!limits || limits.status !== "active") {
            return failure("unauthorized", 401);
        }

        if (Number(limits.recent_count) >= MAX_CREATIONS_PER_MINUTE) {
            const oldest = Number(limits.oldest_recent_creation);
            const retryAfter = Math.max(1, 60 - (now - oldest));

            return failure(
                "rate_limit_exceeded",
                429,
                undefined,
                retryAfter
            );
        }

        if (
            Number(limits.unfinished_count) >=
            MAX_UNFINISHED_SESSIONS
        ) {
            return failure(
                "too_many_sessions",
                429,
                undefined,
                3
            );
        }

        throw new Error("Session creation was rejected unexpectedly.");
    }

    return {
        sessionId,
        authorizationUrl,
        sessionExpiresAt: new Date(
            expiresAt * 1000
        ).toISOString()
    };
}

const CALLBACK_FAILURE_CODES = new Set([
    "authorization_denied",
    "provider_bad_response"
]);

const PROFILE_FIELDS = Object.freeze([
    "userId",
    "userName",
    "email"
]);

function sessionBindings(claims) {
    return [
        claims.sessionId,
        claims.clientId,
        claims.broker,
        claims.credentials.appId,
        claims.expiresAt
    ];
}

function normalizeProviderResult(value) {
    if (!isRecord(value) || !isRecord(value.token)) {
        throw new ProviderError("provider_bad_response");
    }

    const sourceToken = value.token;

    if (
        typeof sourceToken.accessToken !== "string" ||
        sourceToken.accessToken.length === 0 ||
        sourceToken.accessToken.length > 16384 ||
        typeof sourceToken.tokenType !== "string" ||
        sourceToken.tokenType.length === 0 ||
        sourceToken.tokenType.length > 32
    ) {
        throw new ProviderError("provider_bad_response");
    }

    const token = {
        accessToken: sourceToken.accessToken,
        tokenType: sourceToken.tokenType
    };

    if (sourceToken.tokenExpiresAt !== undefined) {
        const expiry = sourceToken.tokenExpiresAt;

        if (typeof expiry !== "string") {
            throw new ProviderError("provider_bad_response");
        }

        const date = new Date(expiry);

        if (
            !Number.isFinite(date.getTime()) ||
            date.toISOString() !== expiry
        ) {
            throw new ProviderError("provider_bad_response");
        }

        token.tokenExpiresAt = expiry;
    }

    const result = { token };

    if (value.profile !== undefined) {
        if (!isRecord(value.profile)) {
            throw new ProviderError("provider_bad_response");
        }

        const profile = {};

        for (const field of PROFILE_FIELDS) {
            const fieldValue = value.profile[field];

            if (fieldValue === undefined) {
                continue;
            }

            if (
                typeof fieldValue !== "string" ||
                fieldValue.length > 512
            ) {
                throw new ProviderError("provider_bad_response");
            }

            profile[field] = fieldValue;
        }

        if (Object.keys(profile).length > 0) {
            result.profile = profile;
        }
    }

    return result;
}

async function failProcessingSession(env, claims, failureCode) {
    return env.DB.prepare(`
        UPDATE auth_sessions
        SET
            status = 'failed',
            failure_code = ?
        WHERE session_id = ?
          AND corex_client_id = ?
          AND broker = ?
          AND provider_app_id = ?
          AND api_version = 3
          AND expires_at = ?
          AND status = 'processing'
    `).bind(
        failureCode,
        ...sessionBindings(claims)
    ).run();
}

export async function completeAuthCallback(env, {
    broker,
    state,
    query
}) {
    if (!env?.DB) {
        throw new Error("Database binding is missing.");
    }

    if (
        typeof broker !== "string" ||
        !/^[a-z0-9_-]{2,32}$/.test(broker) ||
        typeof state !== "string" ||
        state.length > 4096
    ) {
        return "invalid";
    }

    const provider = getProvider(broker);

    if (!provider) {
        return "invalid";
    }

    const claims = await openOAuthState(env, state);

    if (
        !claims ||
        claims.broker !== broker ||
        !isRecord(claims.credentials)
    ) {
        return "invalid";
    }

    const credentials = claims.credentials;

    if (
        provider.validateCredentials(credentials) ||
        typeof credentials.appId !== "string"
    ) {
        return "invalid";
    }

    const now = Math.floor(Date.now() / 1000);
    const bindings = sessionBindings(claims);

    // Expired state cannot start an exchange.
    if (claims.expiresAt <= now) {
        await env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'expired',
                failure_code = 'session_expired'
            WHERE session_id = ?
              AND corex_client_id = ?
              AND broker = ?
              AND provider_app_id = ?
              AND api_version = 3
              AND expires_at = ?
              AND status = 'pending'
        `).bind(...bindings).run();

        return "expired";
    }

    const callback = provider.parseCallback(query);

    if (!isRecord(callback)) {
        return "invalid";
    }

    // The provider has already converted its broker-specific denial
    // into a CoreX error code.
    if (callback.error !== undefined) {
        if (!CALLBACK_FAILURE_CODES.has(callback.error)) {
            return "invalid";
        }

        const denied = await env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'failed',
                callback_received_at = ?,
                failure_code = ?
            WHERE session_id = ?
              AND corex_client_id = ?
              AND broker = ?
              AND provider_app_id = ?
              AND api_version = 3
              AND expires_at = ?
              AND expires_at > ?
              AND status = 'pending'
              AND EXISTS (
                  SELECT 1
                  FROM corex_clients
                  WHERE corex_client_id = ?
                    AND status = 'active'
              )
        `).bind(
            now,
            callback.error,
            ...bindings,
            now,
            claims.clientId
        ).run();

        return denied.meta?.changes === 1
            ? "failed"
            : "invalid";
    }

    if (
        typeof callback.code !== "string" ||
        callback.code.length === 0 ||
        callback.code.length > 2048
    ) {
        return "invalid";
    }

    // Atomic one-time callback claim. Only the first valid callback
    // can move a session from pending to processing.
    const claimed = await env.DB.prepare(`
        UPDATE auth_sessions
        SET
            status = 'processing',
            callback_received_at = ?
        WHERE session_id = ?
          AND corex_client_id = ?
          AND broker = ?
          AND provider_app_id = ?
          AND api_version = 3
          AND expires_at = ?
          AND expires_at > ?
          AND status = 'pending'
          AND EXISTS (
              SELECT 1
              FROM corex_clients
              WHERE corex_client_id = ?
                AND status = 'active'
          )
    `).bind(
        now,
        ...bindings,
        now,
        claims.clientId
    ).run();

    if (claimed.meta?.changes !== 1) {
        return "invalid";
    }

    try {
        const redirectUri = getBrokerRedirectUri(env, broker);

        const providerResult = await provider.exchange({
            code: callback.code,
            credentials,
            redirectUri
        });

        const result = normalizeProviderResult(providerResult);

        const ciphertext = await sealTokenResult(env, {
            sessionId: claims.sessionId,
            broker,
            result
        });

        const readyAt = Math.floor(Date.now() / 1000);

        // Keep a ready token available for up to 60 seconds after
        // its original expiry, without shortening its existing lifetime.
        const stored = await env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'ready',
                result_ciphertext = ?,
                expires_at = MAX(expires_at, ?) + 60
            WHERE session_id = ?
              AND corex_client_id = ?
              AND broker = ?
              AND provider_app_id = ?
              AND api_version = 3
              AND expires_at = ?
              AND status = 'processing'
              AND result_ciphertext IS NULL
              AND EXISTS (
                  SELECT 1
                  FROM corex_clients
                  WHERE corex_client_id = ?
                    AND status = 'active'
              )
        `).bind(
            ciphertext,
            readyAt,
            ...bindings,
            claims.clientId
        ).run();

        return stored.meta?.changes === 1
            ? "received"
            : "invalid";
    } catch (error) {
        if (error instanceof ProviderError) {
            await failProcessingSession(
                env,
                claims,
                error.code
            );

            return "failed";
        }

        // Do not expose unexpected errors or broker responses.
        console.error("Authentication callback processing failed", {
            errorName: error instanceof Error
                ? error.name
                : "UnknownError"
        });

        await failProcessingSession(
            env,
            claims,
            "authentication_unavailable"
        );

        return "unavailable";
    }
}

const RESULT_FAILURES = Object.freeze({
    authorization_denied: [ "authorization_denied", 409 ],
    exchange_rejected: [ "exchange_rejected", 409 ],
    provider_unreachable: [ "provider_unreachable", 409 ],
    provider_unavailable: [ "provider_unavailable", 409 ],
    provider_bad_response: [ "provider_bad_response", 409 ],
    authentication_unavailable: [ "service_unavailable", 503 ]
});

function getFailureResult(code) {
    const [error, httpStatus] =
        RESULT_FAILURES[code] ?? [
            "authentication_failed",
            409
        ];

    return failure(error, httpStatus);
}

async function expireSession(env, sessionId, clientId, now) {
    await env.DB.prepare(`
        UPDATE auth_sessions
        SET
            status = 'expired',
            result_ciphertext = NULL,
            failure_code = 'session_expired'
        WHERE session_id = ?
          AND corex_client_id = ?
          AND api_version = 3
          AND status IN ('pending', 'ready')
          AND expires_at <= ?
    `).bind(sessionId, clientId, now).run();
}

export async function getAuthSessionResult(
    env,
    { sessionId, clientId }
) {
    if (!env?.DB) {
        throw new Error("Database binding is missing.");
    }

    if (
        typeof sessionId !== "string" ||
        sessionId.length === 0 ||
        sessionId.length > 64
    ) {
        return failure("session_not_found", 404);
    }

    // Always restrict lookup to the owning, active client.
    const findSession = () => env.DB.prepare(`
        SELECT
            s.broker,
            s.status,
            s.expires_at,
            s.failure_code,
            s.result_ciphertext
        FROM auth_sessions s
        WHERE s.session_id = ?
          AND s.corex_client_id = ?
          AND s.api_version = 3
          AND EXISTS (
              SELECT 1
              FROM corex_clients c
              WHERE c.corex_client_id = s.corex_client_id
                AND c.status = 'active'
          )
    `).bind(sessionId, clientId).first();

    let session = await findSession();

    if (!session) {
        return failure("session_not_found", 404);
    }

    let now = Math.floor(Date.now() / 1000);

    if (
        ["pending", "ready"].includes(session.status) &&
        session.expires_at <= now
    ) {
        await expireSession(env, sessionId, clientId, now);
        return failure("expired", 410);
    }

    switch (session.status) {
        case "pending":
        case "processing":
            return { status: "pending" };

        case "failed":
            return getFailureResult(session.failure_code);

        case "cancelled":
            return failure("cancelled", 410);

        case "expired":
            return failure("expired", 410);

        case "retrieved":
            return failure("already_retrieved", 410);

        case "ready":
            break;

        default:
            throw new Error("Unexpected V3 session status.");
    }

    if (!session.result_ciphertext) {
        throw new Error("Ready session has no stored result.");
    }

    // Decrypt first. If decryption fails, the result remains available
    // for retry rather than being consumed accidentally.
    const result = await openTokenResult(env, {
        sessionId,
        broker: session.broker,
        ciphertext: session.result_ciphertext
    });

    now = Math.floor(Date.now() / 1000);

    // Claim retrieval and delete ciphertext in one D1 transaction.
    // Only one concurrent request can change ready -> retrieved.
    const batch = await env.DB.batch([
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'retrieved',
                retrieved_at = ?
            WHERE session_id = ?
              AND corex_client_id = ?
              AND broker = ?
              AND api_version = 3
              AND status = 'ready'
              AND result_ciphertext = ?
              AND expires_at > ?
              AND EXISTS (
                  SELECT 1
                  FROM corex_clients
                  WHERE corex_client_id = ?
                    AND status = 'active'
              )
        `).bind(
            now,
            sessionId,
            clientId,
            session.broker,
            session.result_ciphertext,
            now,
            clientId
        ),

        env.DB.prepare(`
            UPDATE auth_sessions
            SET result_ciphertext = NULL
            WHERE session_id = ?
              AND corex_client_id = ?
              AND api_version = 3
              AND status = 'retrieved'
              AND result_ciphertext IS NOT NULL
        `).bind(sessionId, clientId)
    ]);

    if (batch[0]?.meta?.changes !== 1) {
        // Another request may have retrieved or invalidated it first.
        session = await findSession();

        if (!session) {
            return failure("session_not_found", 404);
        }

        if (session.status === "retrieved") {
            return failure("already_retrieved", 410);
        }

        if (session.status === "failed") {
            return getFailureResult(session.failure_code);
        }

        if (session.status === "cancelled") {
            return failure("cancelled", 410);
        }

        if (session.status === "expired") {
            return failure("expired", 410);
        }

        if (
            ["pending", "processing"].includes(session.status)
        ) {
            return { status: "pending" };
        }

        if (
            session.status === "ready" &&
            session.expires_at <= now
        ) {
            await expireSession(env, sessionId, clientId, now);
            return failure("expired", 410);
        }

        throw new Error("Token retrieval could not be claimed.");
    }

    if (batch[1]?.meta?.changes !== 1) {
        throw new Error("Retrieved token ciphertext was not cleared.");
    }

    return {
        status: "completed",
        broker: session.broker,
        ...result
    };
}