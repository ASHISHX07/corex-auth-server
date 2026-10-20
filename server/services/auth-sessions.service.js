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

async function createAuthSession(env, clientId) {
    if (!env.DB) {
        throw new Error("Database binding is missing");
    }

    const redirectUri = env.UPSTOX_REDIRECT_URI;

    if (
        typeof redirectUri !== "string" ||
        !redirectUri.startsWith("https://")
    ) {
        throw new Error("Callback URI is not configured");
    }

    const sessionId = crypto.randomUUID();
    const state = randomBase64Url();
    const retrievalSecret = randomBase64Url();

    const stateHash = await sha256Hex(state);
    const retrievalSecretHash = await sha256Hex(retrievalSecret);

    const now = Math.floor(Date.now() / 1000);
    const ttlSeconds = 300;
    const expiresAt = now + ttlSeconds;

    const result = await env.DB
        .prepare(`
            INSERT INTO auth_sessions (
                session_id,
                client_id,
                state_hash,
                retrieval_secret_hash,
                status,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
            sessionId,
            clientId,
            stateHash,
            retrievalSecretHash,
            "pending",
            now,
            expiresAt
        )
        .run();

    if (!result.success) {
        throw new Error("Failed to create authentication session");
    }

    const authorizationUrl = new URL(
        "https://api.upstox.com/v2/login/authorization/dialog"
    );

    authorizationUrl.searchParams.set("client_id", clientId);
    authorizationUrl.searchParams.set(
        "redirect_uri",
        redirectUri
    );
    authorizationUrl.searchParams.set("response_type", "code");
    authorizationUrl.searchParams.set("state", state);

    return {
        sessionId,
        retrievalSecret,
        authorizationUrl: authorizationUrl.toString(),
        expiresInSeconds: ttlSeconds,
        expiresAt: new Date(expiresAt * 1000).toISOString()
    };
}

export { createAuthSession };