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

export { createAuthSession };