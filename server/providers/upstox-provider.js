const AUTHORIZATION_ENDPOINT = "https://api.upstox.com/v2/login/authorization/dialog";

const CALLBACK_PATH = "/auth/upstox/callback";

export function createUpstoxProvider(env) {
    const redirectUri = env.UPSTOX_REDIRECT_URI;

    if (typeof redirectUri !== "string") {
        throw new Error("Upstox redirect URI is not configured");
    }

    const parsedRedirectUri = new URL(redirectUri);

    if (
        parsedRedirectUri.protocol !== "https:" ||
        parsedRedirectUri.pathname !== CALLBACK_PATH
    ) {
        throw new Error("Invalid Upstox redirect URI configuration");
    }

    return {
        name: "upstox",
        callbackPath: CALLBACK_PATH,

        buildAuthorizationUrl({ appId, state }) {
            const url = new URL(AUTHORIZATION_ENDPOINT);

            url.searchParams.set("client_id", appId);
            url.searchParams.set("redirect_uri", redirectUri);
            url.searchParams.set("response_type", "code");
            url.searchParams.set("state", state);

            return url.toString();
        }
    };
}
