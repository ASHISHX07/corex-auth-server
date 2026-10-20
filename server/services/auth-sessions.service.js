import { getProvider } from "../providers/provider-registry.js";
import { sha256Hex } from "../security/crypto.js";

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

async function createAuthSession(env, { broker, appId, corexClientId }) {
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
                corex_client_id,
                broker,
                provider_app_id,
                state_hash,
                retrieval_secret_hash,
                status,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            sessionId,
            corexClientId,
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

async function getAuthSessionResult(env, { sessionId, retrievalSecret }) {
    if (
        typeof sessionId !== "string" ||
        sessionId.length > 100 ||
        typeof retrievalSecret !== "string" ||
        retrievalSecret.length < 40 ||
        retrievalSecret.length > 100
    ) {
        return { status: "not_found" };
    }

    const secretHash = await sha256Hex(retrievalSecret);

    const findSession = () => env.DB
        .prepare(`
            SELECT status, expires_at, failure_code
            FROM auth_sessions
            WHERE session_id = ?
              AND retrieval_secret_hash = ?
        `)
        .bind(sessionId, secretHash)
        .first();

    const expireSession = () => {
        const now = Math.floor(Date.now() / 1000);

        return env.DB
            .prepare(`
                UPDATE auth_sessions
                SET
                    status = 'expired',
                    authorization_code = NULL,
                    failure_code = 'session_expired'
                WHERE session_id = ?
                    AND retrieval_secret_hash = ?
                    AND status IN ('pending', 'code_received')
                    AND expires_at <= ?
            `)
            .bind(sessionId, secretHash, now)
            .run();
    };

    let session = await findSession();

    if (!session) {
        return { status: "not_found" };
    }

    let now = Math.floor(Date.now() / 1000);

    if (
        ["pending", "code_received"].includes(session.status) &&
        session.expires_at <= now
    ) {
        await expireSession();
        session = await findSession();

        if (!session) {
            return { status: "not_found" };
        }
    }

    if (session.status === "pending") {
        return {
            status: "pending",
            expiresAt: new Date(
                session.expires_at * 1000
            ).toISOString()
        };
    }

    if (session.status === "failed") {
        return {
            status: "failed",
            error: session.failure_code ?? "authorization_failed"
        };
    }

    if (session.status === "expired") {
        return { status: "expired" };
    }

    if (session.status === "retrieved") {
        return { status: "already_retrieved" };
    }

    if (session.status !== "code_received") {
        return { status: "unavailable" };
    }

    now = Math.floor(Date.now() / 1000);

    // Claim the code and clear it in one D1 batch transaction.
    const results = await env.DB.batch([
        env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'retrieved',
                code_retrieved_at = ?
            WHERE session_id = ?
            AND retrieval_secret_hash = ?
            AND status = 'code_received'
            AND expires_at > ?
            RETURNING authorization_code
        `).bind(now, sessionId, secretHash, now),

        env.DB.prepare(`
            UPDATE auth_sessions
            SET authorization_code = NULL
            WHERE session_id = ?
            AND status = 'retrieved'
        `).bind(sessionId)
    ]);

    const claimedCode = results[0]?.results?.[0]?.authorization_code;

    if (
        typeof claimedCode === "string" &&
        claimedCode.length > 0
    ) {
        return {
            status: "completed",
            authorizationCode: claimedCode
        };
    }

    // Another request may have claimed the code first.
    session = await findSession();

    if (!session) {
        return { status: "not_found" };
    }

    now = Math.floor(Date.now() / 1000);

    if (
        ["pending", "code_received"].includes(session.status) &&
        session.expires_at <= now
    ) {
        await expireSession();
        session = await findSession();

        if (!session) {
            return { status: "not_found" };
        }
    }

    if (session.status === "retrieved") {
        return { status: "already_retrieved" };
    }

    if (session.status === "expired") {
        return { status: "expired" };
    }

    return { status: session.status };
}

export { createAuthSession, receiveAuthCode, failAuthSession, getAuthSessionResult };