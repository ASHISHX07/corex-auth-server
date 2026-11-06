import test from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../server/gateway/app.js";

test("health endpoint returns a successful JSON response", async () => {
    const server = createApp({}).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
        const response = await fetch(`${baseUrl}/api/health`);

        assert.equal(response.status, 200);
        assert.equal(
            response.headers.get("cache-control"),
            "no-store"
        );

        assert.deepEqual(
            await response.json(),
            { status: "ok" }
        );
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => {
                if (error) reject(error);
                else resolve();
            });
        });
    }
});

test("unknown API endpoints return standardized JSON errors", async () => {
    const server = createApp({}).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const address = server.address();

    try {
        const response = await fetch(
            `http://127.0.0.1:${address.port}/api/unknown`
        );

        assert.equal(response.status, 404);

        assert.deepEqual(
            await response.json(),
            {
                error: "not_found",
                message: "The requested API endpoint was not found."
            }
        );
    } finally {
        await new Promise((resolve, reject) => {
            server.close(error => {
                if (error) reject(error);
                else resolve();
            });
        });
    }
});