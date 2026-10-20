import { getProvider } from "../providers/provider-registry.js";

function randomBase64Url(byteLength = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
    
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

async function sha256Hex(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest("SHA-256", bytes);

    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function createAuthSession(env, { broker, appId }) {
    if (!env.DB) {
        throw new Error("Database binding is missing");
    }

    const provider = getProvider(env, broker);

    if (!provider) {
        const error = new Error("Unsupported broker");
        error.code = "UNSUPPORTED_BROKER";
        throw error;
    }

    const sessionId = crypto.randomUUID();
    const state = randomBase64Url();
    const retrievalSecret = randomBase64Url();

    const [stateHash, retrievalSecretHash] = await Promise.all([
        sha256Hex(state),
        sha256Hex(retrievalSecret)
    ]);

    const now = Math.floor(Date.now() / 1000);
    const ttlSeconds = 300;
    const expiresAt = now + ttlSeconds;

    const result = await env.DB
        .prepare(`
            INSERT INTO auth_sessions (
                session_id,
                broker,
                provider_app_id,
                state_hash,
                retrieval_secret_hash,
                status,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            sessionId,
            broker,
            appId,
            stateHash,
            retrievalSecretHash,
            "pending",
            now,
            expiresAt
        )
        .run();

    if (!result.success) {
        throw new Error("Session creation failed");
    }

    const authorizationUrl = provider.buildAuthorizationUrl({
        appId,
        state
    });

    return {
        sessionId,
        broker,
        retrievalSecret,
        authorizationUrl,
        expiresInSeconds: ttlSeconds,
        expiresAt: new Date(expiresAt * 1000).toISOString()
    };
}

async function receiveAuthCode(env, { broker, code, state }) {
    if (
        typeof code !== "string" ||
        code.length === 0 ||
        code.length > 2048 ||
        typeof state !== "string" ||
        state.length === 0 ||
        state.length > 1024
    ) return false;

    const stateHash = await sha256Hex(state);
    const now = Math.floor(Date.now() / 1000);

    const result = await env.DB
        .prepare(`
            UPDATE auth_sessions
            SET
                authorization_code = ?,
                status = 'code_received',
                callback_received_at = ?
            WHERE
                broker = ?
                AND state_hash = ?
                AND status = 'pending'
                AND expires_at > ?
        `)
        .bind(code, now, broker, stateHash, now)
        .run();

    // Exactly one pending session must have accepted this callback.
    return result.success && result.meta.changes === 1;
}

async function failAuthSession(
    env,
    { broker, state }
) {
    if (
        typeof state !== "string" ||
        state.length === 0 ||
        state.length > 1024
    ) {
        return false;
    }

    const stateHash = await sha256Hex(state);
    const now = Math.floor(Date.now() / 1000);

    const result = await env.DB
        .prepare(`
            UPDATE auth_sessions
            SET
                status = CASE
                    WHEN expires_at <= ? THEN 'expired'
                    ELSE 'failed'
                END,
                failure_code = 'authorization_denied',
                callback_received_at = ?
            WHERE
                broker = ?
                AND state_hash = ?
                AND status = 'pending'
        `)
        .bind(now, now, broker, stateHash)
        .run();

    return result.success && result.meta.changes === 1;
}

export { createAuthSession, receiveAuthCode, failAuthSession };