import { ProviderError } from "./provider-error.js";

const AUTHORIZATION_ENDPOINT = "https://api.upstox.com/v2/login/authorization/dialog";
const TOKEN_ENDPOINT = "https://api.upstox.com/v2/login/authorization/token";
const CALLBACK_PATH = "/auth/upstox/callback";
const EXCHANGE_TIMEOUT_MS = 8000;

// Upstox access tokens expire at 03:30 IST (= 22:00 UTC) the next day.
function nextTokenExpiry(now = new Date()) {
    const expiry = new Date(Date.UTC(
        now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 22, 0, 0
    ));
    if (expiry <= now) expiry.setUTCDate(expiry.getUTCDate() + 1);
    return expiry.toISOString();
}

/**
 * Provider contract (every broker implements this shape):
 *   name, callbackPath
 *   validateCredentials({ appId, appSecret }) -> null | "appId" | "appSecret"
 *   buildAuthorizationUrl({ appId, state })   -> string
 *   exchangeCode({ code, appId, appSecret })  -> { accessToken, tokenType, expiresAt, profile }
 *       throws ProviderError(code) on any failure
 */
export function createUpstoxProvider(env) {
    const redirectUri = env.UPSTOX_REDIRECT_URI;

    if (typeof redirectUri !== "string") {
        throw new Error("Upstox redirect URI is not configured");
    }

    const parsed = new URL(redirectUri);

    if (parsed.protocol !== "https:" || parsed.pathname !== CALLBACK_PATH) {
        throw new Error("Invalid Upstox redirect URI configuration");
    }

    return {
        name: "upstox",
        callbackPath: CALLBACK_PATH,

        // Returns null when valid, otherwise the NAME of the offending field (never its value).
        validateCredentials({ appId, appSecret }) {
            if (typeof appId !== "string" || !/^[\w-]{8,128}$/.test(appId)) return "appId";
            if (typeof appSecret !== "string" || appSecret.length < 4 || appSecret.length > 256) return "appSecret";
            return null;
        },

        buildAuthorizationUrl({ appId, state }) {
            const url = new URL(AUTHORIZATION_ENDPOINT);

            url.searchParams.set("client_id", appId);
            url.searchParams.set("redirect_uri", redirectUri);
            url.searchParams.set("response_type", "code");
            url.searchParams.set("state", state);

            return url.toString();
        },

        async exchangeCode({ code, appId, appSecret }) {
            let response;

            try {
                response = await fetch(TOKEN_ENDPOINT, {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                    body: new URLSearchParams({
                        code,
                        client_id: appId,
                        client_secret: appSecret,
                        redirect_uri: redirectUri,
                        grant_type: "authorization_code"
                    }),
                    signal: AbortSignal.timeout(EXCHANGE_TIMEOUT_MS)
                });
            } catch {
                throw new ProviderError("provider_unreachable");
            }

            if (!response.ok) {
                throw new ProviderError(
                    response.status >= 500 ? "provider_unavailable" : "exchange_rejected"
                );
            }

            let body;
            try {
                body = await response.json();
            } catch {
                throw new ProviderError("provider_bad_response");
            }

            if (typeof body?.access_token !== "string" || body.access_token.length === 0) {
                throw new ProviderError("provider_bad_response");
            }

            // Whitelist: only pass on fields CoreX clients need.
            const profile = {};
            for (const [from, to] of [["user_id", "userId"], ["user_name", "userName"], ["email", "email"]]) {
                if (typeof body[from] === "string") profile[to] = body[from];
            }

            return {
                accessToken: body.access_token,
                tokenType: "Bearer",
                expiresAt: nextTokenExpiry(),
                profile
            };
        }
    };
}
