import test from "node:test";
import assert from "node:assert/strict";

import { sha256Hex } from "../server/security/hashing.js";
import { requireClientAuth } from "../server/gateway/client-auth.js";

const API_KEY = `cx_${"A".repeat(43)}`;

async function createClient({
    scopes = '["auth"]',
    status = "active",
    lastSeen = 0
} = {}) {
    return {
        corex_client_id: "client-123",
        display_name: "Test CoreX",
        api_key_hash: await sha256Hex(API_KEY),
        scopes,
        status,
        last_seen_at: lastSeen
    };
}

function createEnvironment(client) {
    const updates = [];

    const DB = {
        prepare(sql) {
            let parameters = [];

            return {
                bind(...values) {
                    parameters = values;
                    return this;
                },

                async first() {
                    if (!sql.includes("FROM corex_clients")) {
                        throw new Error("Unexpected query.");
                    }

                    return (
                        parameters[0] === client?.api_key_hash &&
                        client?.status === "active"
                    ) ? client : null;
                },

                async run() {
                    updates.push({ sql, parameters });

                    if (client?.status !== "active") {
                        return {
                            success: true,
                            meta: { changes: 0 }
                        };
                    }

                    client.last_seen_at = parameters[0];

                    return {
                        success: true,
                        meta: { changes: 1 }
                    };
                }
            };
        }
    };

    return {
        env: { DB },
        updates
    };
}

async function invoke(env, authorization) {
    const req = {
        corexClient: null,
        get(name) {
            return name.toLowerCase() === "authorization"
                ? authorization
                : undefined;
        }
    };

    const res = {
        statusCode: 200,
        headers: {},
        body: null,

        set(name, value) {
            this.headers[name.toLowerCase()] = value;
            return this;
        },

        status(code) {
            this.statusCode = code;
            return this;
        },

        json(body) {
            this.body = body;
            return this;
        }
    };

    let nextCalled = false;

    await requireClientAuth(env, "auth")(
        req,
        res,
        () => {
            nextCalled = true;
        }
    );

    return { req, res, nextCalled };
}

test("missing client key returns 401", async () => {
    const { env } = createEnvironment(null);

    const { res, nextCalled } = await invoke(env, undefined);

    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, "unauthorized");
    assert.equal(res.headers["www-authenticate"], "Bearer");
    assert.equal(nextCalled, false);
});

test("unprefixed client keys are rejected", async () => {
    const { env } = createEnvironment(null);

    const { res } = await invoke(
        env,
        `Bearer ${"A".repeat(43)}`
    );

    assert.equal(res.statusCode, 401);
});

test("unknown client key returns 401", async () => {
    const client = await createClient();
    const { env } = createEnvironment(client);

    const { res, nextCalled } = await invoke(
        env,
        `Bearer cx_${"B".repeat(43)}`
    );

    assert.equal(res.statusCode, 401);
    assert.equal(nextCalled, false);
});

test("revoked clients cannot authenticate", async () => {
    const client = await createClient({ status: "revoked" });
    const { env } = createEnvironment(client);

    const { res } = await invoke(env, `Bearer ${API_KEY}`);

    assert.equal(res.statusCode, 401);
});

test("valid client authenticates and exposes its identity", async () => {
    const client = await createClient({
        lastSeen: Math.floor(Date.now() / 1000)
    });

    const { env } = createEnvironment(client);

    const { req, res, nextCalled } = await invoke(
        env,
        `Bearer ${API_KEY}`
    );

    assert.equal(res.statusCode, 200);
    assert.equal(nextCalled, true);

    assert.deepEqual(req.corexClient, {
        id: "client-123",
        displayName: "Test CoreX",
        scopes: ["auth"]
    });
});

test("client without the required scope receives 403", async () => {
    const client = await createClient({ scopes: "[]" });
    const { env } = createEnvironment(client);

    const { res, nextCalled } = await invoke(
        env,
        `Bearer ${API_KEY}`
    );

    assert.equal(res.statusCode, 403);
    assert.equal(res.body.error, "forbidden_scope");
    assert.equal(nextCalled, false);
});

test("last_seen_at updates when older than five minutes", async () => {
    const client = await createClient({ lastSeen: 0 });
    const { env, updates } = createEnvironment(client);

    const { nextCalled } = await invoke(env, `Bearer ${API_KEY}`);

    assert.equal(nextCalled, true);
    assert.equal(updates.length, 1);
    assert.ok(client.last_seen_at > 0);
});

test("last_seen_at is not updated on every request", async () => {
    const client = await createClient({
        lastSeen: Math.floor(Date.now() / 1000)
    });

    const { env, updates } = createEnvironment(client);

    const { nextCalled } = await invoke(env, `Bearer ${API_KEY}`);

    assert.equal(nextCalled, true);
    assert.equal(updates.length, 0);
});

test("malformed stored scopes fail closed", async () => {
    const client = await createClient({ scopes: "not-json" });
    const { env } = createEnvironment(client);

    const { res, nextCalled } = await invoke(
        env,
        `Bearer ${API_KEY}`
    );

    assert.equal(res.statusCode, 503);
    assert.equal(res.body.error, "authentication_unavailable");
    assert.equal(nextCalled, false);
});

test("missing database binding returns 503", async () => {
    const { res, nextCalled } = await invoke(
        {},
        `Bearer ${API_KEY}`
    );

    assert.equal(res.statusCode, 503);
    assert.equal(nextCalled, false);
});