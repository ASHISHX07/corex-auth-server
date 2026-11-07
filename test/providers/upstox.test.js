import test from "node:test";
import assert from "node:assert/strict";

import { getProvider } from "../../server/brokers/registry.js";

const provider = getProvider("upstox");

const credentials = {
    appId: "APP-ID-123",
    appSecret: "APP-SECRET-123"
};

const redirectUri =
    "https://auth.example.com/auth/upstox/callback";

async function withMockFetch(mock, callback) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock;

    try {
        await callback();
    } finally {
        globalThis.fetch = originalFetch;
    }
}

test("Upstox exchanges the authorization code and normalizes the result", async () => {
    let request;

    await withMockFetch(async (url, options) => {
        request = {
            url: String(url),
            options
        };

        return Response.json({
            access_token: "ACCESS-TOKEN",
            extended_token: "DO-NOT-RETURN",
            user_id: "USER-123",
            user_name: "Example User",
            email: "user@example.com",
            broker: "UPSTOX"
        });
    }, async () => {
        const result = await provider.exchange({
            code: "AUTH-CODE",
            credentials,
            redirectUri
        });

        // Verify the HTTP request after the provider has completed.
        assert.equal(
            request.url,
            "https://api.upstox.com/v2/login/authorization/token"
        );

        assert.equal(request.options.method, "POST");

        const body = Object.fromEntries(
            new URLSearchParams(request.options.body)
        );

        assert.deepEqual(body, {
            code: "AUTH-CODE",
            client_id: credentials.appId,
            client_secret: credentials.appSecret,
            redirect_uri: redirectUri,
            grant_type: "authorization_code"
        });

        // Verify the normalized CoreX response.
        assert.equal(result.token.accessToken, "ACCESS-TOKEN");
        assert.equal(result.token.tokenType, "Bearer");

        assert.ok(
            Date.parse(result.token.tokenExpiresAt) > Date.now()
        );

        assert.deepEqual(result.profile, {
            userId: "USER-123",
            userName: "Example User",
            email: "user@example.com"
        });

        assert.equal(
            JSON.stringify(result).includes("DO-NOT-RETURN"),
            false
        );

        assert.equal(request.options.redirect, "manual");
    });
});

test("Upstox network failure returns provider_unreachable", async () => {
    await withMockFetch(async () => {
        throw new Error("Network error");
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "provider_unreachable"
        );
    });
});

test("Upstox HTTP 401 returns exchange_rejected", async () => {
    await withMockFetch(async () => {
        return new Response("Unauthorized", {
            status: 401
        });
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "exchange_rejected"
        );
    });
});

test("Upstox HTTP 503 returns provider_unavailable", async () => {
    await withMockFetch(async () => {
        return new Response("Unavailable", {
            status: 503
        });
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "provider_unavailable"
        );
    });
});

test("Upstox malformed response returns provider_bad_response", async () => {
    await withMockFetch(async () => {
        return new Response("not-json", {
            status: 200
        });
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "provider_bad_response"
        );
    });
});

test("Upstox response without access token is rejected", async () => {
    await withMockFetch(async () => {
        return Response.json({
            user_id: "USER-123"
        });
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "provider_bad_response"
        );
    });
});

test("Upstox rejects unexpected redirects without following them", async () => {
    await withMockFetch(async () => {
        return new Response(null, {
            status: 302,
            headers: {
                Location: "https://example.com/token"
            }
        });
    }, async () => {
        await assert.rejects(
            provider.exchange({
                code: "AUTH-CODE",
                credentials,
                redirectUri
            }),
            error => error.code === "provider_bad_response"
        );
    });
});