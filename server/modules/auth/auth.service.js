import { getProvider } from "../../brokers/registry.js";
import { getBrokerRedirectUri } from "../../gateway/config.js";
import { randomBase64Url } from "../../security/encoding.js";
import { sealOAuthState } from "../../security/seal.js";

const SESSION_TTL_SECONDS = 300;
const MAX_UNFINISHED_SESSIONS = 5;
const MAX_CREATIONS_PER_MINUTE = 10;
const MAX_CREDENTIAL_BYTES = 1024;

const ACTIVE_STATUSES = [
    "pending",
    "processing",
    "ready"
];

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