import test from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../server/gateway/app.js";

async function withServer(callback) {
    const server = createApp({}).listen(0);

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
    }
}

test("health endpoint returns JSON, request ID and no-store", async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/api/health`);

        assert.equal(response.status, 200);
        assert.equal(
            response.headers.get("cache-control"),
            "no-store"
        );

        assert.match(
            response.headers.get("x-request-id") ?? "",
            /^[0-9a-f-]{36}$/i
        );

        assert.deepEqual(
            await response.json(),
            { status: "ok" }
        );
    });
});

test("each request receives a unique request ID", async () => {
    await withServer(async baseUrl => {
        const first = await fetch(`${baseUrl}/api/health`);
        const second = await fetch(`${baseUrl}/api/health`);

        assert.notEqual(
            first.headers.get("x-request-id"),
            second.headers.get("x-request-id")
        );
    });
});

test("unknown API routes return standardized JSON errors", async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/api/unknown`);

        assert.equal(response.status, 404);

        assert.deepEqual(
            await response.json(),
            {
                error: "not_found",
                message: "The requested API endpoint was not found."
            }
        );

        assert.ok(response.headers.get("x-request-id"));
    });
});

test("malformed JSON returns invalid_json", async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/api/test`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: "{"
        });

        assert.equal(response.status, 400);

        assert.equal(
            (await response.json()).error,
            "invalid_json"
        );
    });
});

test("oversized JSON returns payload_too_large", async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/api/test`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify("x".repeat(3000))
        });

        assert.equal(response.status, 413);

        assert.equal(
            (await response.json()).error,
            "payload_too_large"
        );
    });
});

test("non-JSON request bodies are rejected", async () => {
    await withServer(async baseUrl => {
        const response = await fetch(`${baseUrl}/api/test`, {
            method: "POST",
            headers: {
                "Content-Type": "text/plain"
            },
            body: "hello"
        });

        assert.equal(response.status, 415);

        assert.equal(
            (await response.json()).error,
            "unsupported_media_type"
        );
    });
});