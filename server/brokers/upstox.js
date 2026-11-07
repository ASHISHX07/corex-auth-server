import { ProviderError } from "./provider-error.js";

const AUTHORIZATION_URL =
    "https://api.upstox.com/v2/login/authorization/dialog";

const TOKEN_URL =
    "https://api.upstox.com/v2/login/authorization/token";

const EXCHANGE_TIMEOUT_MS = 8000;

const CREDENTIAL_FIELDS = Object.freeze([
    "appId",
    "appSecret"
]);

const INDIA_OFFSET_MS = 330 * 60 * 1000;

function isRecord(value) {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}

function validateCredentials(credentials) {
    if (!isRecord(credentials)) {
        return "credentials";
    }

    if (
        typeof credentials.appId !== "string" ||
        !credentials.appId.trim() ||
        credentials.appId.length > 256
    ) {
        return "appId";
    }

    if (
        typeof credentials.appSecret !== "string" ||
        !credentials.appSecret.trim() ||
        credentials.appSecret.length > 512
    ) {
        return "appSecret";
    }

    return null;
}

// Upstox tokens expire at 03:30 Asia/Kolkata.
function getTokenExpiry(now = new Date()) {
    const indiaNow = new Date(
        now.getTime() + INDIA_OFFSET_MS
    );

    const expiry = new Date(Date.UTC(
        indiaNow.getUTCFullYear(),
        indiaNow.getUTCMonth(),
        indiaNow.getUTCDate(),
        3,
        30
    ));

    if (expiry <= indiaNow) {
        expiry.setUTCDate(expiry.getUTCDate() + 1);
    }

    return new Date(
        expiry.getTime() - INDIA_OFFSET_MS
    ).toISOString();
}

function parseCallback(query) {
    if (!isRecord(query)) {
        return { error: "provider_bad_response" };
    }

    if (
        typeof query.error === "string" &&
        query.error.length > 0
    ) {
        return { error: "authorization_denied" };
    }

    if (
        typeof query.code !== "string" ||
        query.code.length === 0 ||
        query.code.length > 2048
    ) {
        return { error: "provider_bad_response" };
    }

    return {
        code: query.code
    };
}

async function exchange({
    code,
    credentials,
    redirectUri
}) {
    if (
        validateCredentials(credentials) ||
        typeof code !== "string" ||
        code.length === 0 ||
        typeof redirectUri !== "string"
    ) {
        throw new TypeError("Invalid provider exchange input.");
    }

    let response;

    const startedAt = Date.now();

    try {
        response = await fetch(TOKEN_URL, {
            redirect: "error",
            method: "POST",
            headers: {
                Accept: "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
                code,
                client_id: credentials.appId,
                client_secret: credentials.appSecret,
                redirect_uri: redirectUri,
                grant_type: "authorization_code"
            }),
            signal: AbortSignal.timeout(EXCHANGE_TIMEOUT_MS)
        });
    } catch (error) {
        const errorName =
            error instanceof Error ? error.name : "UnknownError";
    
        const errorMessage =
            error instanceof Error
                ? error.message.toLowerCase()
                : "";
    
        const failureType =
            errorName === "TimeoutError" || errorName === "AbortError"
                ? "timeout"
                : errorMessage.includes("redirect")
                    ? "redirect_rejected"
                    : "network_or_fetch_error";
    
        console.error("Upstox token exchange fetch failed", {
            failureType,
            errorName,
            elapsedMs: Date.now() - startedAt
        });
    
        throw new ProviderError("provider_unreachable");
    }

    if (!response.ok) {
        throw new ProviderError(
            response.status >= 500 || response.status === 429
                ? "provider_unavailable"
                : "exchange_rejected"
        );
    }

    let body;

    try {
        body = await response.json();
    } catch {
        throw new ProviderError("provider_bad_response");
    }

    if (
        !isRecord(body) ||
        typeof body.access_token !== "string" ||
        !body.access_token ||
        body.access_token.length > 16384
    ) {
        throw new ProviderError("provider_bad_response");
    }

    const profile = {};

    if (typeof body.user_id === "string") {
        profile.userId = body.user_id;
    }

    if (typeof body.user_name === "string") {
        profile.userName = body.user_name;
    }

    if (typeof body.email === "string") {
        profile.email = body.email;
    }

    return {
        token: {
            accessToken: body.access_token,
            tokenType: "Bearer",
            tokenExpiresAt: getTokenExpiry()
        },

        ...(Object.keys(profile).length > 0 && { profile })
    };
}

export const upstoxProvider = Object.freeze({
    id: "upstox",

    credentialFields: CREDENTIAL_FIELDS,

    validateCredentials,

    buildAuthorizationUrl({
        credentials,
        state,
        redirectUri
    }) {
        if (
            validateCredentials(credentials) ||
            typeof state !== "string" ||
            !state ||
            typeof redirectUri !== "string" ||
            !redirectUri
        ) {
            throw new TypeError("Invalid provider authorization input.");
        }

        const url = new URL(AUTHORIZATION_URL);

        url.searchParams.set("client_id", credentials.appId);
        url.searchParams.set("redirect_uri", redirectUri);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("state", state);

        return url.toString();
    },

    parseCallback,

    exchange
});