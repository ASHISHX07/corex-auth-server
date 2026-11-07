import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { createApp } from "../server/gateway/app.js";
import { createD1 } from "../test-support/d1.js";

import { randomBase64Url } from "../server/security/encoding.js";
import { createAdminSessionToken } from "../server/security/admin-session.js";

const MIGRATIONS_DIRECTORY = fileURLToPath(
    new URL("../db/migrations/", import.meta.url)
);

test("admin can monitor requests and sessions and invalidate an active session", async () => {
    const DB = createD1(MIGRATIONS_DIRECTORY);
    const now = Math.floor(Date.now() / 1000);

    const env = {
        DB,
        COREX_ADMIN_SESSION_SECRET: randomBase64Url(32)
    };

    await DB.prepare(`
        INSERT INTO corex_clients (
            corex_client_id,
            api_key_hash,
            display_name,
            status,
            created_at,
            scopes
        )
        VALUES (?, ?, ?, 'active', ?, '["auth"]')
    `).bind(
        "monitor-client",
        "monitor-hash",
        "CoreX Monitor Test",
        now
    ).run();

    async function insertSession({
        id,
        broker,
        status,
        failureCode = null,
        callbackReceivedAt = null,
        retrievedAt = null
    }) {
        await DB.prepare(`
            INSERT INTO auth_sessions (
                session_id,
                corex_client_id,
                broker,
                provider_app_id,
                api_version,
                status,
                created_at,
                expires_at,
                callback_received_at,
                retrieved_at,
                failure_code
            )
            VALUES (?, 'monitor-client', ?, 'APP-ID', 3, ?, ?, ?, ?, ?, ?)
        `).bind(
            id,
            broker,
            status,
            now - 60,
            now + 300,
            callbackReceivedAt,
            retrievedAt,
            failureCode
        ).run();
    }

    await insertSession({
        id: "ready-session",
        broker: "upstox",
        status: "ready",
        callbackReceivedAt: now - 30
    });

    await insertSession({
        id: "failed-session",
        broker: "upstox",
        status: "failed",
        failureCode: "exchange_rejected",
        callbackReceivedAt: now - 25
    });

    await insertSession({
        id: "pending-session",
        broker: "fyers",
        status: "pending"
    });

    await DB.prepare(`
        INSERT INTO request_logs (
            request_id,
            method,
            path,
            status_code,
            duration_ms,
            corex_client_id,
            broker,
            created_at
        )
        VALUES
            ('request-success', 'POST', '/api/v3/auth/sessions', 201, 35, 'monitor-client', 'upstox', ?),
            ('request-failure', 'POST', '/api/v3/auth/sessions', 401, 12, 'monitor-client', 'upstox', ?)
    `).bind(now - 10, now - 5).run();

    const token = await createAdminSessionToken(
        env,
        "operator-one"
    );

    const server = createApp(env).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    async function request(method, path) {
        return fetch(`${baseUrl}${path}`, {
            method,
            headers: {
                Cookie: `corex_admin_session=${token}`,
                Origin: baseUrl
            }
        });
    }

    try {
        // Overview.
        const overviewResponse = await request(
            "GET",
            "/api/v3/admin/overview?period=24h"
        );

        assert.equal(overviewResponse.status, 200);

        const overview = await overviewResponse.json();

        assert.equal(overview.requests.total, 2);
        assert.equal(overview.requests.successful, 1);
        assert.equal(overview.requests.failed, 1);

        assert.equal(overview.clients.active, 1);

        assert.equal(overview.sessions.total, 3);
        assert.equal(overview.sessions.ready, 1);
        assert.equal(overview.sessions.failed, 1);
        assert.equal(overview.sessions.pending, 1);

        assert.deepEqual(overview.failureReasons, [
            { code: "exchange_rejected", count: 1 }
        ]);

        const upstox = overview.brokerStats.find(
            item => item.broker === "upstox"
        );

        assert.equal(upstox.successRate, 50);

        // Request history.
        const requestsResponse = await request(
            "GET",
            "/api/v3/admin/requests?period=24h&limit=25"
        );

        assert.equal(requestsResponse.status, 200);

        const requests = await requestsResponse.json();

        assert.equal(requests.items.length, 2);
        assert.ok(requests.items[0].requestId);
        assert.equal("authorization" in requests.items[0], false);

        // Session list and details.
        const sessionsResponse = await request(
            "GET",
            "/api/v3/admin/sessions?broker=upstox&status=ready"
        );

        assert.equal(sessionsResponse.status, 200);

        const sessions = await sessionsResponse.json();

        assert.equal(sessions.items.length, 1);
        assert.equal(sessions.items[0].apiVersion, 3);
        assert.equal(sessions.items[0].status, "ready");

        const detailResponse = await request(
            "GET",
            "/api/v3/admin/sessions/ready-session"
        );

        assert.equal(detailResponse.status, 200);

        const detail = await detailResponse.json();

        assert.equal(detail.callbackReceivedAt !== null, true);
        assert.equal("resultCiphertext" in detail, false);
        assert.equal("authorizationCode" in detail, false);

        // Invalidate the pending session.
        const invalidateResponse = await request(
            "POST",
            "/api/v3/admin/sessions/pending-session/invalidate"
        );

        assert.equal(invalidateResponse.status, 200);

        assert.deepEqual(await invalidateResponse.json(), {
            sessionId: "pending-session",
            status: "cancelled",
            invalidated: true
        });

        const cancelled = await DB.prepare(`
            SELECT status, failure_code
            FROM auth_sessions
            WHERE session_id = 'pending-session'
        `).first();

        assert.equal(cancelled.status, "cancelled");
        assert.equal(cancelled.failure_code, "admin_invalidated");

        // Session invalidation must be audited.
        const auditResponse = await request(
            "GET",
            "/api/v3/admin/audit"
        );

        assert.equal(auditResponse.status, 200);

        const audit = await auditResponse.json();

        assert.ok(
            audit.items.some(item =>
                item.action === "session.invalidate" &&
                item.targetId === "pending-session" &&
                item.actor === "operator-one"
            )
        );
    } finally {
        await new Promise(resolve => server.close(resolve));
        DB.close();
    }
});