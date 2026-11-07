import test from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../server/gateway/app.js";

const HTML_TEMPLATE = `<!doctype html>
<html
    data-corex-broker="__COREX_BROKER__"
    data-corex-status="__COREX_STATUS__"
>
<body></body>
</html>`;

async function withServer(env, callback) {
    const server = createApp(env).listen(0);

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

function createEnv(assetResponse = new Response(HTML_TEMPLATE)) {
    return {
        ASSETS: {
            async fetch() {
                return assetResponse;
            }
        }
    };
}

test("renders the shared authorization page with an allowlisted status and broker", async () => {
    const env = createEnv();

    await withServer(env, async baseUrl => {
        const response = await fetch(
            `${baseUrl}/auth/response?broker=upstox&status=received`
        );

        assert.equal(response.status, 200);

        const html = await response.text();

        assert.match(
            html,
            /data-corex-broker="upstox"/
        );

        assert.match(
            html,
            /data-corex-status="received"/
        );

        assert.equal(
            response.headers.get("content-type")?.includes("text/html"),
            true
        );
    });
});

test("normalizes unknown broker and status values without reflecting user input", async () => {
    const env = createEnv();

    await withServer(env, async baseUrl => {
        const response = await fetch(
            `${baseUrl}/auth/response` +
            `?broker=${encodeURIComponent('upstox" onload="alert(1)')}` +
            `&status=${encodeURIComponent("<script>alert(1)</script>")}`
        );

        assert.equal(response.status, 200);

        const html = await response.text();

        assert.match(
            html,
            /data-corex-broker="corex"/
        );

        assert.match(
            html,
            /data-corex-status="invalid"/
        );

        assert.doesNotMatch(html, /alert\(1\)/);
        assert.doesNotMatch(html, /<script>/);
    });
});

test("authorization page has restrictive browser security headers", async () => {
    const env = createEnv();

    await withServer(env, async baseUrl => {
        const response = await fetch(
            `${baseUrl}/auth/response?broker=upstox&status=received`
        );

        assert.equal(
            response.headers.get("cache-control"),
            "no-store"
        );

        assert.equal(
            response.headers.get("referrer-policy"),
            "no-referrer"
        );

        assert.equal(
            response.headers.get("x-content-type-options"),
            "nosniff"
        );

        assert.equal(
            response.headers.get("x-frame-options"),
            "DENY"
        );

        assert.equal(
            response.headers.get("x-robots-tag"),
            "noindex, nofollow"
        );

        const csp = response.headers.get(
            "content-security-policy"
        );

        assert.match(csp, /default-src 'none'/);
        assert.match(csp, /script-src 'self'/);
        assert.match(csp, /style-src 'self'/);
        assert.match(csp, /connect-src 'none'/);
        assert.match(csp, /frame-ancestors 'none'/);
    });
});

test("returns a safe error when the authorization page asset is missing", async () => {
    const env = createEnv(
        new Response("Not found", { status: 404 })
    );

    await withServer(env, async baseUrl => {
        const response = await fetch(
            `${baseUrl}/auth/response?broker=upstox&status=received`
        );

        assert.equal(response.status, 503);

        assert.equal(
            await response.text(),
            "CoreX authorization page is temporarily unavailable."
        );

        assert.equal(
            response.headers.get("cache-control"),
            "no-store"
        );
    });
});