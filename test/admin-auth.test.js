import test from "node:test";
import assert from "node:assert/strict";

import { pbkdf2Sync, randomBytes } from "node:crypto";

import { createApp } from "../server/gateway/app.js";
import { toBase64Url, randomBytes as secureBytes } from "../server/security/encoding.js";

test("two administrators can log in, access /me and log out", async () => {
    const users = ["operator-one", "operator-two"].map((username, index) => {
        const password = `TestPassword-${index + 1}`;
        const salt = randomBytes(16);

        const hash = pbkdf2Sync(
            password,
            salt,
            25000,
            32,
            "sha256"
        );

        return {
            username,
            password,
            record: {
                username,
                salt: salt.toString("base64url"),
                hash: hash.toString("base64url")
            }
        };
    });

    const env = {
        COREX_ADMIN_USERS: toBase64Url(
            new TextEncoder().encode(
                JSON.stringify(users.map(user => user.record))
            )
        ),

        COREX_ADMIN_SESSION_SECRET: toBase64Url(secureBytes(32)),

        ADMIN_LOGIN_LIMITER: {
            async limit() {
                return { success: true };
            }
        }
    };

    const server = createApp(env).listen(0);

    await new Promise((resolve, reject) => {
        server.once("listening", resolve);
        server.once("error", reject);
    });

    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    const headers = {
        "Content-Type": "application/json",
        Origin: baseUrl
    };

    try {
        for (const user of users) {
            const login = await fetch(
                `${baseUrl}/api/v3/admin/login`,
                {
                    method: "POST",
                    headers,
                    body: JSON.stringify({
                        username: user.username,
                        password: user.password
                    })
                }
            );

            assert.equal(login.status, 200);

            const loginBody = await login.json();

            assert.equal(loginBody.authenticated, true);
            assert.equal(loginBody.username, user.username);

            const cookie = login.headers.get("set-cookie")
                .split(";")[0];

            const me = await fetch(
                `${baseUrl}/api/v3/admin/me`,
                { headers: { Cookie: cookie } }
            );

            assert.equal(me.status, 200);

            assert.deepEqual(await me.json(), {
                authenticated: true,
                username: user.username
            });

            const logout = await fetch(
                `${baseUrl}/api/v3/admin/logout`,
                {
                    method: "POST",
                    headers: {
                        ...headers,
                        Cookie: cookie
                    }
                }
            );
            
            assert.equal(logout.status, 200);
            
            const clearedCookie = logout.headers.get("set-cookie");
            
            assert.ok(clearedCookie);
            assert.match(clearedCookie, /Max-Age=0/);
            assert.match(clearedCookie, /HttpOnly/);
            
            // A browser processes Max-Age=0 and removes the cookie.
            // fetch() doesn't maintain a cookie jar, so simulate that here.
            const afterLogout = await fetch(
                `${baseUrl}/api/v3/admin/me`
            );
            
            assert.equal(afterLogout.status, 401);
        }
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
});