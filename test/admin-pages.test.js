import test from "node:test";
import assert from "node:assert/strict";

import { createApp } from "../server/gateway/app.js";
import { randomBase64Url } from "../server/security/encoding.js";
import { createAdminSessionToken } from "../server/security/admin-session.js";

test("admin pages require a valid signed administrator cookie", async () => {
    const env = {
        COREX_ADMIN_SESSION_SECRET: randomBase64Url(32),

        ASSETS: {
            async fetch(request) {
                const pathname = new URL(request.url).pathname;

                return new Response(`asset:${pathname}`, {
                    headers: {
                        "Content-Type": "text/html"
                    }
                });
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

    try {
        // An unauthenticated visitor is redirected to login.
        const denied = await fetch(`${baseUrl}/`, {
            redirect: "manual"
        });

        assert.equal(denied.status, 303);
        assert.equal(denied.headers.get("location"), "/login.html");

        // Login HTML remains publicly accessible.
        const login = await fetch(`${baseUrl}/login.html`);

        assert.equal(login.status, 200);
        assert.match(await login.text(), /asset:\/login\.html/);

        assert.equal(
            login.headers.get("cache-control"),
            "no-store"
        );

        // A valid administrator cookie grants dashboard access.
        const dashboard = await fetch(`${baseUrl}/`, {
            headers: {
                Cookie: `corex_admin_session=${token}`
            }
        });

        assert.equal(dashboard.status, 200);
        assert.match(await dashboard.text(), /asset:\/index\.html/);

        assert.match(
            dashboard.headers.get("content-security-policy"),
            /frame-ancestors 'none'/
        );

        // An authenticated administrator visiting login is redirected.
        const authenticatedLogin = await fetch(
            `${baseUrl}/login.html`,
            {
                headers: {
                    Cookie: `corex_admin_session=${token}`
                },
                redirect: "manual"
            }
        );

        assert.equal(authenticatedLogin.status, 303);
        assert.equal(
            authenticatedLogin.headers.get("location"),
            "/"
        );
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});