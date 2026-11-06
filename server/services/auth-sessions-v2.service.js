import { getProvider } from "../brokers/provider-registry.js";
import { ProviderError } from "../brokers/provider-error.js";
import {
    sealState, openState, encryptForClient, importClientPublicKey
} from "../security/legacy-v2.js";

const SESSION_TTL_SECONDS = 300;
const RETRIEVAL_GRACE_SECONDS = 60;
const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * Creates a session. The broker app secret and the client's public key are sealed
 * into the OAuth `state` (AES-256-GCM, key held only as a Worker secret), so the
 * secret is never written to D1 and never logged.
 */
export async function createAuthSessionV2(env, { broker, appId, appSecret, clientPublicKey, corexClientId }) {
    const provider = getProvider(env, broker);

    if (!provider) throw Object.assign(new Error("Unsupported broker"), { code: "UNSUPPORTED_BROKER" });

    const badField = provider.validateCredentials({ appId, appSecret });

    if (badField) {
        throw Object.assign(new Error("Invalid credentials"), { code: "INVALID_REQUEST", field: badField });
    }

    // Fail now, not after the one-time code has been spent.
    try {
        await importClientPublicKey(clientPublicKey);
    } catch {
        throw Object.assign(new Error("Invalid public key"), { code: "INVALID_REQUEST", field: "clientPublicKey" });
    }

    const sessionId = crypto.randomUUID();
    const now = nowSeconds();
    const expiresAt = now + SESSION_TTL_SECONDS;

    const state = await sealState(env, {
        sid: sessionId, cid: corexClientId, b: broker,
        aid: appId, sec: appSecret, cpk: clientPublicKey, exp: expiresAt
    });

    const result = await env.DB.prepare(`
        INSERT INTO auth_sessions (
            session_id, corex_client_id, broker, provider_app_id,
            api_version, status, created_at, expires_at
        ) VALUES (?, ?, ?, ?, 2, 'pending', ?, ?)
    `).bind(sessionId, corexClientId, broker, appId, now, expiresAt).run();

    if (!result.success) throw new Error("Session creation failed");

    return {
        sessionId,
        broker,
        authorizationUrl: provider.buildAuthorizationUrl({ appId, state }),
        expiresInSeconds: SESSION_TTL_SECONDS,
        expiresAt: new Date(expiresAt * 1000).toISOString()
    };
}

/**
 * Handles the broker redirect for a v2 session: claim -> exchange -> encrypt -> store.
 * Returns one of the status-page outcomes: received | failed | invalid | expired.
 */
export async function completeAuthSessionV2(env, provider, { state, code, error }) {
    const claims = await openState(env, state);

    if (!claims || claims.b !== provider.name || typeof claims.sid !== "string") return "invalid";

    const now = nowSeconds();
    if (!(claims.exp > now)) return "expired";

    // Broker said no (user cancelled etc.).
    if (typeof error === "string" && error.length > 0) {
        const denied = await env.DB.prepare(`
            UPDATE auth_sessions
            SET
                status = 'failed',
                failure_code = 'authorization_denied',
                callback_received_at = ?
            WHERE session_id = ?
                AND api_version = 2
                AND status = 'pending'
                AND expires_at > ?
                AND corex_client_id = ?
                AND broker = ?
                AND provider_app_id = ?
                AND EXISTS (
                    SELECT 1 FROM corex_clients c
                    WHERE c.corex_client_id = auth_sessions.corex_client_id
                      AND c.status = 'active'
                )
        `).bind(
            now,
            claims.sid,
            now,
            claims.cid,
            claims.b,
            claims.aid
        ).run();

        return denied.meta.changes === 1 ? "failed" : "invalid";
    }

    if (typeof code !== "string" || code.length === 0 || code.length > 2048) return "invalid";

    // Single-use claim: a replayed callback can never reach the exchange step.
    const claim = await env.DB.prepare(`
        UPDATE auth_sessions
        SET status = 'code_received', callback_received_at = ?
        WHERE session_id = ?
            AND api_version = 2
            AND status = 'pending'
            AND expires_at > ?
            AND corex_client_id = ?
            AND broker = ?
            AND provider_app_id = ?
            AND EXISTS (
                SELECT 1 FROM corex_clients c
                WHERE c.corex_client_id = auth_sessions.corex_client_id
                  AND c.status = 'active'
            )
    `).bind(
        now,
        claims.sid,
        now,
        claims.cid,
        claims.b,
        claims.aid
    ).run();

    if (!claim.success || claim.meta.changes !== 1) return "invalid";

    const fail = async failureCode => {
        await env.DB.prepare(`
            UPDATE auth_sessions SET status = 'failed', failure_code = ?
            WHERE session_id = ? AND status = 'code_received' AND result_ciphertext IS NULL
        `).bind(failureCode, claims.sid).run();
        return "failed";
    };

    let token;
    try {
        token = await provider.exchangeCode({ code, appId: claims.aid, appSecret: claims.sec });
    } catch (err) {
        return fail(err instanceof ProviderError ? err.code : "exchange_failed");
    }

    let envelope;
    try {
        envelope = await encryptForClient(claims.cpk, token, claims.sid);
    } catch {
        return fail("encryption_failed");
    }

    const done = nowSeconds();
    const stored = await env.DB.prepare(`
        UPDATE auth_sessions
        SET result_ciphertext = ?, expires_at = max(expires_at, ?)
        WHERE session_id = ? AND status = 'code_received' AND result_ciphertext IS NULL
    `).bind(JSON.stringify(envelope), done + RETRIEVAL_GRACE_SECONDS, claims.sid).run();

    return stored.meta.changes === 1 ? "received" : "invalid";
}

/** One-time retrieval of the encrypted result. Only the owning client can ask. */
export async function getAuthSessionResultV2(env, { sessionId, corexClientId }) {
    if (typeof sessionId !== "string" || sessionId.length > 64) return { status: "not_found" };

    const find = () => env.DB.prepare(`
        SELECT status, expires_at, failure_code, result_ciphertext IS NOT NULL AS has_result
        FROM auth_sessions
        WHERE session_id = ? AND corex_client_id = ? AND api_version = 2
    `).bind(sessionId, corexClientId).first();

    let session = await find();
    if (!session) return { status: "not_found" };

    const now = nowSeconds();

    if (["pending", "code_received"].includes(session.status) && session.expires_at <= now) {
        await env.DB.prepare(`
            UPDATE auth_sessions
            SET status = 'expired', result_ciphertext = NULL, failure_code = 'session_expired'
            WHERE session_id = ? AND status IN ('pending', 'code_received')
        `).bind(sessionId).run();
        return { status: "expired" };
    }

    switch (session.status) {
        case "pending":
            return { status: "pending", expiresAt: new Date(session.expires_at * 1000).toISOString() };
        case "failed":
            return { status: "failed", error: session.failure_code ?? "authorization_failed" };
        case "expired":
            return { status: "expired" };
        case "retrieved":
            return { status: "already_retrieved" };
    }

    // status === 'code_received'
    if (!session.has_result) return { status: "pending", expiresAt: new Date(session.expires_at * 1000).toISOString() };

    // Claim and wipe atomically (D1 batch = one transaction).
    const [claimed] = await env.DB.batch([
        env.DB.prepare(`
            UPDATE auth_sessions SET status = 'retrieved', code_retrieved_at = ?
            WHERE session_id = ? AND corex_client_id = ? AND status = 'code_received'
              AND result_ciphertext IS NOT NULL AND expires_at > ?
            RETURNING result_ciphertext
        `).bind(now, sessionId, corexClientId, now),
        env.DB.prepare(`
            UPDATE auth_sessions SET result_ciphertext = NULL
            WHERE session_id = ? AND status = 'retrieved' AND result_ciphertext IS NOT NULL
        `).bind(sessionId)
    ]);

    const ciphertext = claimed?.results?.[0]?.result_ciphertext;

    if (typeof ciphertext === "string") {
        return { status: "completed", encrypted: JSON.parse(ciphertext) };
    }

    // Lost a race or expired between the read and the claim.
    session = await find();
    return { status: session?.status === "retrieved" ? "already_retrieved" : "expired" };
}
