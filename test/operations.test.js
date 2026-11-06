import test from "node:test";
import assert from "node:assert/strict";

import { fileURLToPath } from "node:url";

import { createApp } from "../server/gateway/app.js";
import { createD1 } from "../test-support/d1.js";
import { runMaintenance } from "../server/maintenance.js";

const MIGRATIONS_DIRECTORY = fileURLToPath(
    new URL("../db/migrations/", import.meta.url)
);

const DAY = 86400;

test("request logging stores metadata without query strings", async () => {
    const DB = createD1(MIGRATIONS_DIRECTORY);
    const tasks = [];

    const app = createApp(
        { DB },
        task => tasks.push(task)
    );

    const server = app.listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    try {
        const response = await fetch(
            `http://127.0.0.1:${server.address().port}` +
            "/api/health?secret=DO-NOT-LOG"
        );

        await Promise.all(tasks);

        assert.equal(response.status, 200);
        assert.equal(tasks.length, 1);

        const requestId = response.headers.get("x-request-id");

        const row = await DB.prepare(`
            SELECT *
            FROM request_logs
            WHERE request_id = ?
        `).bind(requestId).first();

        assert.ok(row);
        assert.equal(row.path, "/api/health");
        assert.equal(row.method, "GET");
        assert.equal(row.status_code, 200);
        assert.ok(row.duration_ms >= 0);

        assert.equal(
            JSON.stringify(row).includes("DO-NOT-LOG"),
            false
        );
    } finally {
        await Promise.all(tasks);

        await new Promise(resolve => server.close(resolve));

        DB.close();
    }
});

test("maintenance expires sessions and applies retention periods", async () => {
    const DB = createD1(MIGRATIONS_DIRECTORY);
    const now = Math.floor(Date.now() / 1000);

    try {
        await DB.prepare(`
            INSERT INTO corex_clients (
                corex_client_id,
                api_key_hash,
                display_name,
                status,
                created_at
            )
            VALUES (?, ?, ?, 'active', ?)
        `).bind(
            "maintenance-client",
            "maintenance-test-hash",
            "Maintenance Test",
            now
        ).run();

        async function addSession({
            id,
            status,
            createdAt,
            expiresAt,
            ciphertext = null
        }) {
            await DB.prepare(`
                INSERT INTO auth_sessions (
                    session_id,
                    corex_client_id,
                    broker,
                    provider_app_id,
                    api_version,
                    result_ciphertext,
                    status,
                    created_at,
                    expires_at
                )
                VALUES (?, ?, 'upstox', 'APP-ID', 3, ?, ?, ?, ?)
            `).bind(
                id,
                "maintenance-client",
                ciphertext,
                status,
                createdAt,
                expiresAt
            ).run();
        }

        await addSession({
            id: "stale-ready",
            status: "ready",
            createdAt: now - DAY,
            expiresAt: now - 1,
            ciphertext: "temporary-ciphertext"
        });

        await addSession({
            id: "old-retrieved",
            status: "retrieved",
            createdAt: now - 91 * DAY,
            expiresAt: now - 91 * DAY + 300
        });

        await DB.prepare(`
            INSERT INTO request_logs (
                request_id,
                method,
                path,
                status_code,
                duration_ms,
                created_at
            )
            VALUES
                ('old-log', 'GET', '/api/health', 200, 1, ?),
                ('recent-log', 'GET', '/api/health', 200, 1, ?)
        `).bind(
            now - 31 * DAY,
            now - 1
        ).run();

        await DB.prepare(`
            INSERT INTO admin_audit (
                id, at, actor, action, target_type, target_id
            )
            VALUES
                ('old-audit', ?, 'admin', 'client.create', 'client', 'old'),
                ('recent-audit', ?, 'admin', 'client.create', 'client', 'new')
        `).bind(
            now - 366 * DAY,
            now - 1
        ).run();

        await runMaintenance({ DB }, now);

        const expired = await DB.prepare(`
            SELECT status, result_ciphertext
            FROM auth_sessions
            WHERE session_id = 'stale-ready'
        `).first();

        assert.equal(expired.status, "expired");
        assert.equal(expired.result_ciphertext, null);

        const oldSession = await DB.prepare(`
            SELECT session_id
            FROM auth_sessions
            WHERE session_id = 'old-retrieved'
        `).first();

        assert.equal(oldSession, null);

        const oldLog = await DB.prepare(`
            SELECT request_id
            FROM request_logs
            WHERE request_id = 'old-log'
        `).first();

        assert.equal(oldLog, null);

        const recentLog = await DB.prepare(`
            SELECT request_id
            FROM request_logs
            WHERE request_id = 'recent-log'
        `).first();

        assert.ok(recentLog);

        const oldAudit = await DB.prepare(`
            SELECT id
            FROM admin_audit
            WHERE id = 'old-audit'
        `).first();

        assert.equal(oldAudit, null);

        const recentAudit = await DB.prepare(`
            SELECT id
            FROM admin_audit
            WHERE id = 'recent-audit'
        `).first();

        assert.ok(recentAudit);
    } finally {
        DB.close();
    }
});