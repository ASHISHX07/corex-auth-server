import test from "node:test";
import assert from "node:assert/strict";

import { fileURLToPath } from "node:url";

import { createApp } from "../server/gateway/app.js";
import { createD1 } from "./d1.js";

import { sha256Hex } from "../server/security/hashing.js";

import {
    randomBase64Url
} from "../server/security/encoding.js";

import {
    openOAuthState
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