import test from "node:test";
import assert from "node:assert/strict";

import { fileURLToPath } from "node:url";
import { createApp } from "../server/gateway/app.js";
import { createD1 } from "./d1.js";
import { sha256Hex } from "../server/security/hashing.js";
import { randomBase64Url } from "../server/security/encoding.js";
import {
    openOAuthState,
    sealOAuthState,
    openTokenResult
} from "../server/security/seal.js";

const MIGRATIONS_DIRECTORY = fileURLToPath(
    new URL("../db/migrations/", import.meta.url)
);

const APP_ID = "UPSTOX-APPLICATION-ID";
const APP_SECRET = "UPSTOX-APPLICATION-SECRET";

async function createContext() {
    const DB = createD1(MIGRATIONS_DIRECTORY);

    const env = {
        DB,
        COREX_MASTER_KEY: randomBase64Url(32),
        PUBLIC_BASE_URL: "https://auth.example.com"
    };

    const clientId = "test-client";
    const apiKey = `cx_${randomBase64Url(32)}`;

    await DB.prepare(`
        INSERT INTO corex_clients (
            corex_client_id,
            api_key_hash,
            key_hint,
            display_name,
            scopes,
            status,
            created_at,
            created_by
        )
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
    `).bind(
        clientId,
        await sha256Hex(apiKey),
        apiKey.slice(-4),
        "Test CoreX",
        '["auth"]',
        Math.floor(Date.now() / 1000),
        "test"
    ).run();

    return {
        DB,
        env,
        clientId,
        apiKey
    };
}

async function withServer(context, callback) {
    const server = createApp(context.env).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    try {
        await callback(baseUrl);
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => {
                if (error) reject(error);
                else resolve();
            });
        });

        context.DB.close();
    }
}

async function createSession(baseUrl, apiKey, overrides = {}) {
    return fetch(`${baseUrl}/api/v3/auth/sessions`, {
        method: "POST",
        headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            broker: "upstox",
            credentials: {
                appId: APP_ID,
                appSecret: APP_SECRET
            },
            ...overrides
        })
    });
}

test("creates a session with sealed credentials and a standardized response", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await createSession(
            baseUrl,
            context.apiKey
        );

        assert.equal(response.status, 201);
        assert.equal(
            response.headers.get("cache-control"),
            "no-store"
        );

        assert.ok(response.headers.get("x-request-id"));

        const body = await response.json();

        assert.deepEqual(
            Object.keys(body).sort(),
            [
                "authorizationUrl",
                "sessionExpiresAt",
                "sessionId"
            ].sort()
        );

        assert.equal(typeof body.sessionId, "string");
        assert.equal(typeof body.authorizationUrl, "string");

        const expiresAt = Date.parse(body.sessionExpiresAt);

        assert.ok(Number.isFinite(expiresAt));
        assert.ok(
            expiresAt > Date.now() + 4 * 60 * 1000 &&
            expiresAt <= Date.now() + 5 * 60 * 1000 + 1000
        );

        const authorizationUrl = new URL(body.authorizationUrl);

        assert.equal(
            authorizationUrl.origin + authorizationUrl.pathname,
            "https://api.upstox.com/v2/login/authorization/dialog"
        );

        assert.equal(
            authorizationUrl.searchParams.get("redirect_uri"),
            "https://auth.example.com/auth/upstox/callback"
        );

        const state = authorizationUrl.searchParams.get("state");

        assert.ok(state.startsWith("v3."));
        assert.ok(!body.authorizationUrl.includes(APP_SECRET));

        // The callback state contains the credentials, but only as ciphertext.
        const claims = await openOAuthState(
            context.env,
            state
        );

        assert.deepEqual(claims, {
            sessionId: body.sessionId,
            clientId: context.clientId,
            broker: "upstox",
            expiresAt: Math.floor(expiresAt / 1000),
            credentials: {
                appId: APP_ID,
                appSecret: APP_SECRET
            }
        });

        // D1 contains only metadata, never the OAuth state or app secret.
        const row = await context.DB.prepare(`
            SELECT *
            FROM auth_sessions
            WHERE session_id = ?
        `).bind(body.sessionId).first();

        assert.equal(row.api_version, 3);
        assert.equal(row.broker, "upstox");
        assert.equal(row.provider_app_id, APP_ID);
        assert.equal(row.status, "pending");
        assert.equal(row.authorization_code, null);
        assert.equal(row.result_ciphertext, null);

        assert.equal(JSON.stringify(row).includes(APP_SECRET), false);
        assert.equal(JSON.stringify(row).includes(state), false);
    });
});

test("rejects requests without an authenticated CoreX client", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await fetch(
            `${baseUrl}/api/v3/auth/sessions`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    broker: "upstox",
                    credentials: {
                        appId: APP_ID,
                        appSecret: APP_SECRET
                    }
                })
            }
        );

        assert.equal(response.status, 401);

        assert.equal(
            (await response.json()).error,
            "unauthorized"
        );
    });
});

test("rejects unsupported brokers", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await createSession(
            baseUrl,
            context.apiKey,
            { broker: "unsupported" }
        );

        assert.equal(response.status, 400);

        assert.equal(
            (await response.json()).error,
            "unsupported_broker"
        );
    });
});

test("validates broker-specific credentials", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await createSession(
            baseUrl,
            context.apiKey,
            {
                credentials: {
                    appId: APP_ID
                }
            }
        );

        assert.equal(response.status, 400);

        assert.deepEqual(
            await response.json(),
            {
                error: "invalid_request",
                message: "The request contains invalid data.",
                field: "credentials.appSecret"
            }
        );
    });
});

test("rejects credentials larger than 1 KB", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await createSession(
            baseUrl,
            context.apiKey,
            {
                credentials: {
                    appId: APP_ID,
                    appSecret: "X".repeat(1100)
                }
            }
        );

        assert.equal(response.status, 413);

        assert.equal(
            (await response.json()).error,
            "payload_too_large"
        );
    });
});

test("rejects undeclared credential fields", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        const response = await createSession(
            baseUrl,
            context.apiKey,
            {
                credentials: {
                    appId: APP_ID,
                    appSecret: APP_SECRET,
                    unexpectedSecret: "DO-NOT-ACCEPT"
                }
            }
        );

        assert.equal(response.status, 400);

        assert.equal(
            (await response.json()).field,
            "credentials.unexpectedSecret"
        );
    });
});

test("enforces five unfinished sessions per client", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        for (let i = 0; i < 5; i++) {
            const response = await createSession(
                baseUrl,
                context.apiKey
            );

            assert.equal(response.status, 201);
        }

        const response = await createSession(
            baseUrl,
            context.apiKey
        );

        assert.equal(response.status, 429);
        assert.equal(response.headers.get("retry-after"), "3");

        assert.equal(
            (await response.json()).error,
            "too_many_sessions"
        );

        const count = await context.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM auth_sessions
            WHERE corex_client_id = ?
              AND api_version = 3
              AND status IN ('pending', 'processing', 'ready')
        `).bind(context.clientId).first();

        assert.equal(count.total, 5);
    });
});

test("enforces ten session creations per minute", async () => {
    const context = await createContext();

    await withServer(context, async baseUrl => {
        for (let i = 0; i < 10; i++) {
            const response = await createSession(
                baseUrl,
                context.apiKey
            );

            assert.equal(response.status, 201);

            // Mark the session finished so the five-open-session limit
            // does not interfere with this rate-limit test.
            await context.DB.prepare(`
                UPDATE auth_sessions
                SET status = 'failed'
                WHERE corex_client_id = ?
                  AND api_version = 3
                  AND status = 'pending'
            `).bind(context.clientId).run();
        }

        const response = await createSession(
            baseUrl,
            context.apiKey
        );

        assert.equal(response.status, 429);

        assert.equal(
            response.headers.get("retry-after") !== null,
            true
        );

        assert.equal(
            (await response.json()).error,
            "rate_limit_exceeded"
        );
    });
});

const UPSTOX_TOKEN_URL =
    "https://api.upstox.com/v2/login/authorization/token";

async function withMockedUpstox(mockResponse, callback) {
    const originalFetch = globalThis.fetch;

    let calls = 0;
    let request = null;

    globalThis.fetch = async (url, options) => {
        if (String(url) === UPSTOX_TOKEN_URL) {
            calls++;

            request = {
                url: String(url),
                options
            };

            return mockResponse(url, options);
        }

        return originalFetch(url, options);
    };

    try {
        return await callback({
            get calls() {
                return calls;
            },

            get request() {
                return request;
            }
        });
    } finally {
        globalThis.fetch = originalFetch;
    }
}

async function callBrokerCallback(
    baseUrl,
    broker,
    state,
    parameters = {}
) {
    const query = new URLSearchParams({
        ...parameters,
        state
    });

    return fetch(
        `${baseUrl}/auth/${broker}/callback?${query}`,
        { redirect: "manual" }
    );
}

function callbackStatus(response, baseUrl) {
    const location = response.headers.get("location");

    return new URL(location, baseUrl)
        .searchParams
        .get("status");
}

test("callback exchanges the code and stores a normalized encrypted result", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => Response.json({
            access_token: "ACCESS-TOKEN",
            extended_token: "DO-NOT-STORE",
            user_id: "USER-123",
            user_name: "Example User",
            email: "user@example.com",
            broker: "UPSTOX"
        }),

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                assert.equal(created.status, 201);

                const session = await created.json();

                const state = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const response = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    state,
                    { code: "AUTH-CODE" }
                );

                assert.equal(response.status, 303);
                assert.equal(
                    callbackStatus(response, baseUrl),
                    "received"
                );

                assert.equal(mock.calls, 1);

                const request = mock.request;

                assert.equal(
                    request.url,
                    UPSTOX_TOKEN_URL
                );

                const form = Object.fromEntries(
                    new URLSearchParams(request.options.body)
                );

                assert.deepEqual(form, {
                    code: "AUTH-CODE",
                    client_id: APP_ID,
                    client_secret: APP_SECRET,
                    redirect_uri:
                        "https://auth.example.com/auth/upstox/callback",
                    grant_type: "authorization_code"
                });

                const row = await context.DB.prepare(`
                    SELECT *
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "ready");
                assert.equal(row.authorization_code, null);
                assert.ok(row.result_ciphertext);

                assert.equal(
                    row.result_ciphertext.includes("ACCESS-TOKEN"),
                    false
                );

                assert.equal(
                    row.result_ciphertext.includes(APP_SECRET),
                    false
                );

                const result = await openTokenResult(
                    context.env,
                    {
                        sessionId: session.sessionId,
                        broker: "upstox",
                        ciphertext: row.result_ciphertext
                    }
                );

                assert.equal(
                    result.token.accessToken,
                    "ACCESS-TOKEN"
                );

                assert.equal(
                    result.token.tokenType,
                    "Bearer"
                );

                assert.ok(
                    Date.parse(result.token.tokenExpiresAt) > Date.now()
                );

                assert.deepEqual(result.profile, {
                    userId: "USER-123",
                    userName: "Example User",
                    email: "user@example.com"
                });

                assert.equal(
                    JSON.stringify(result).includes("DO-NOT-STORE"),
                    false
                );
            });
        }
    );
});

test("replayed callback cannot exchange or store the token twice", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => Response.json({
            access_token: "ACCESS-TOKEN"
        }),

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                const session = await created.json();

                const state = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const first = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    state,
                    { code: "AUTH-CODE" }
                );

                assert.equal(callbackStatus(first, baseUrl), "received");
                assert.equal(mock.calls, 1);

                const replay = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    state,
                    { code: "AUTH-CODE" }
                );

                assert.equal(callbackStatus(replay, baseUrl), "invalid");
                assert.equal(mock.calls, 1);

                const row = await context.DB.prepare(`
                    SELECT status, result_ciphertext
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "ready");
                assert.ok(row.result_ciphertext);
            });
        }
    );
});

test("broker denial marks the session failed without exchanging a token", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => {
            throw new Error("Token exchange must not be called.");
        },

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                const session = await created.json();

                const state = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const response = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    state,
                    { error: "access_denied" }
                );

                assert.equal(callbackStatus(response, baseUrl), "failed");
                assert.equal(mock.calls, 0);

                const row = await context.DB.prepare(`
                    SELECT status, failure_code, result_ciphertext
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "failed");
                assert.equal(row.failure_code, "authorization_denied");
                assert.equal(row.result_ciphertext, null);
            });
        }
    );
});

test("tampered callback state cannot claim a session", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => {
            throw new Error("Token exchange must not be called.");
        },

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                const session = await created.json();

                const state = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const index = 10;

                const tampered =
                    state.slice(0, index) +
                    (state[index] === "A" ? "B" : "A") +
                    state.slice(index + 1);

                const response = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    tampered,
                    { code: "AUTH-CODE" }
                );

                assert.equal(callbackStatus(response, baseUrl), "invalid");
                assert.equal(mock.calls, 0);

                const row = await context.DB.prepare(`
                    SELECT status
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "pending");
            });
        }
    );
});

test("expired callback state cannot start a token exchange", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => {
            throw new Error("Token exchange must not be called.");
        },

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                const session = await created.json();

                const originalState = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const claims = await openOAuthState(
                    context.env,
                    originalState
                );

                const now = Math.floor(Date.now() / 1000);
                const expiredAt = now - 10;

                claims.expiresAt = expiredAt;

                await context.DB.prepare(`
                    UPDATE auth_sessions
                    SET created_at = ?, expires_at = ?
                    WHERE session_id = ?
                `).bind(
                    now - 600,
                    expiredAt,
                    session.sessionId
                ).run();

                const expiredState = await sealOAuthState(
                    context.env,
                    claims
                );

                const response = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    expiredState,
                    { code: "AUTH-CODE" }
                );

                assert.equal(callbackStatus(response, baseUrl), "expired");
                assert.equal(mock.calls, 0);

                const row = await context.DB.prepare(`
                    SELECT status, failure_code
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "expired");
                assert.equal(row.failure_code, "session_expired");
            });
        }
    );
});

test("broker token rejection marks the session failed safely", async () => {
    const context = await createContext();

    await withMockedUpstox(
        async () => new Response(
            '{"message":"Invalid secret"}',
            { status: 401 }
        ),

        async mock => {
            await withServer(context, async baseUrl => {
                const created = await createSession(
                    baseUrl,
                    context.apiKey
                );

                const session = await created.json();

                const state = new URL(session.authorizationUrl)
                    .searchParams
                    .get("state");

                const response = await callBrokerCallback(
                    baseUrl,
                    "upstox",
                    state,
                    { code: "AUTH-CODE" }
                );

                assert.equal(callbackStatus(response, baseUrl), "failed");
                assert.equal(mock.calls, 1);

                const row = await context.DB.prepare(`
                    SELECT status, failure_code, result_ciphertext
                    FROM auth_sessions
                    WHERE session_id = ?
                `).bind(session.sessionId).first();

                assert.equal(row.status, "failed");
                assert.equal(row.failure_code, "exchange_rejected");
                assert.equal(row.result_ciphertext, null);

                assert.equal(
                    JSON.stringify(row).includes("Invalid secret"),
                    false
                );
            });
        }
    );
});