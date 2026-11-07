import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { createApp } from "../server/gateway/app.js";
import { createD1 } from "../test-support/d1.js";

import { randomBase64Url } from "../server/security/encoding.js";
import { sha256Hex } from "../server/security/hashing.js";
import { createAdminSessionToken } from "../server/security/admin-session.js";

const MIGRATIONS_DIRECTORY = fileURLToPath(
    new URL("../db/migrations/", import.meta.url)
);

test("admin can create, manage and revoke a CoreX client", async () => {
    const DB = createD1(MIGRATIONS_DIRECTORY);

    const env = {
        DB,
        COREX_ADMIN_SESSION_SECRET: randomBase64Url(32),

        ADMIN_CLIENT_CREATE_LIMITER: {
            async limit() {
                return { success: true };
            }
        }
    };

    const token = await createAdminSessionToken(env, "operator-one");

    const server = createApp(env).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    async function request(method, path, body) {
        return fetch(`${baseUrl}${path}`, {
            method,
            headers: {
                Cookie: `corex_admin_session=${token}`,
                Origin: baseUrl,
                ...(body !== undefined && {
                    "Content-Type": "application/json"
                })
            },
            ...(body !== undefined && {
                body: JSON.stringify(body)
            })
        });
    }

    try {
        // Create client.
        const createdResponse = await request(
            "POST",
            "/api/v3/admin/clients",
            { displayName: "CoreX Desktop" }
        );

        assert.equal(createdResponse.status, 201);

        const created = await createdResponse.json();

        assert.match(created.apiKey, /^cx_[A-Za-z0-9_-]{43}$/);
        assert.deepEqual(created.scopes, ["auth"]);
        assert.equal(created.status, "active");

        // Verify that D1 contains the hash, not the key.
        const stored = await DB.prepare(`
            SELECT *
            FROM corex_clients
            WHERE corex_client_id = ?
        `).bind(created.clientId).first();

        assert.equal(stored.api_key_hash, await sha256Hex(created.apiKey));
        assert.equal(stored.key_hint, created.apiKey.slice(-4));
        assert.equal(stored.created_by, "operator-one");

        assert.equal(
            JSON.stringify(stored).includes(created.apiKey),
            false
        );

        // Listing must never reveal the API key.
        const listResponse = await request(
            "GET",
            "/api/v3/admin/clients"
        );

        assert.equal(listResponse.status, 200);

        const list = await listResponse.json();

        assert.equal(list.items.length, 1);
        assert.equal("apiKey" in list.items[0], false);
        assert.equal("api_key_hash" in list.items[0], false);

        // Add a pending session so revocation has something to cancel.
        const now = Math.floor(Date.now() / 1000);

        await DB.prepare(`
            INSERT INTO auth_sessions (
                session_id,
                corex_client_id,
                broker,
                provider_app_id,
                api_version,
                status,
                created_at,
                expires_at
            )
            VALUES (?, ?, 'upstox', 'APP-ID', 3, 'pending', ?, ?)
        `).bind(
            "test-session",
            created.clientId,
            now,
            now + 300
        ).run();

        // Disable auth scope.
        const scopeResponse = await request(
            "PATCH",
            `/api/v3/admin/clients/${created.clientId}/scopes`,
            { scopes: [] }
        );

        assert.equal(scopeResponse.status, 200);

        const scoped = await scopeResponse.json();

        assert.deepEqual(scoped.scopes, []);
        assert.equal(scoped.changed, true);

        // Revoke the client and cancel its unfinished session.
        const revokeResponse = await request(
            "POST",
            `/api/v3/admin/clients/${created.clientId}/revoke`
        );

        assert.equal(revokeResponse.status, 200);

        const revoked = await revokeResponse.json();

        assert.equal(revoked.status, "revoked");
        assert.equal(revoked.cancelledSessions, 1);

        const session = await DB.prepare(`
            SELECT status, result_ciphertext
            FROM auth_sessions
            WHERE session_id = 'test-session'
        `).first();

        assert.equal(session.status, "cancelled");
        assert.equal(session.result_ciphertext, null);

        // Every client mutation should have an audit entry.
        const auditResponse = await request(
            "GET",
            "/api/v3/admin/audit"
        );

        assert.equal(auditResponse.status, 200);

        const audit = await auditResponse.json();

        assert.deepEqual(
            audit.items.map(item => item.action).sort(),
            [
                "client.create",
                "client.revoke",
                "client.scopes.update"
            ]
        );

        assert.ok(
            audit.items.every(item => item.actor === "operator-one")
        );
    } finally {
        await new Promise(resolve => server.close(resolve));
        DB.close();
    }
});