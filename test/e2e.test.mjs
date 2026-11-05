import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { webcrypto as crypto } from "node:crypto";
import { createD1 } from "./d1-shim.mjs";
import { createApp } from "../server/app.js";
import { sha256Hex } from "../server/security/hashing.js";

import {
    toBase64Url,
    fromBase64Url
} from "../server/security/encoding.js";

import {
    sealState
} from "../server/security/legacy-v2.js";

import {
    sealOAuthState,
    openOAuthState,
    sealTokenResult,
    openTokenResult
} from "../server/security/seal.js";

import { runMaintenance } from "../server/services/maintenance.service.js";

const APP_ID = "UPSTOX-API-KEY-123";
const APP_SECRET = "SUPER-SECRET-VALUE-XYZ";
const ACCESS_TOKEN = "eyJ.fake.ACCESS-TOKEN-PLAINTEXT";
const REDIRECT = "https://corex-server.example.workers.dev/auth/upstox/callback";

const db = createD1(fileURLToPath(new URL("../db/migrations", import.meta.url)));
const limiter = { limit: async () => ({ success: true }) };
const env = {
    DB: db, UPSTOX_REDIRECT_URI: REDIRECT,
    COREX_MASTER_KEY: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    COREX_STATE_KEY: toBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    AUTH_SESSION_LIMITER: limiter, AUTH_POLL_LIMITER: limiter, CALLBACK_LIMITER: limiter
};

// --- fake Upstox; everything else goes to the real fetch ---
const realFetch = globalThis.fetch;
let upstoxMode = "ok", upstoxCalls = [];
globalThis.fetch = async (url, init) => {
    if (String(url).startsWith("https://api.upstox.com/v2/login/authorization/token")) {
        const form = Object.fromEntries(new URLSearchParams(init.body));
        upstoxCalls.push(form);
        if (upstoxMode === "reject") return new Response('{"errors":[{"message":"bad secret SUPER-SECRET"}]}', { status: 401 });
        if (form.client_secret !== APP_SECRET || form.client_id !== APP_ID || form.redirect_uri !== REDIRECT ||
            form.grant_type !== "authorization_code" || form.code !== "AUTHCODE1" && form.code !== "AUTHCODE2")
            return new Response("{}", { status: 400 });
        return Response.json({ access_token: ACCESS_TOKEN, user_id: "U123", user_name: "Test", email: "t@e.st", extended_token: "SHOULD-NOT-LEAK", broker: "UPSTOX" });
    }
    return realFetch(url, init);
};

// --- client key + CoreX client row ---
const API_KEY = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
await db.prepare("INSERT INTO corex_clients (corex_client_id, api_key_hash, display_name, status, created_at) VALUES (?,?,?,?,?)")
    .bind("client-1", await sha256Hex(API_KEY), "Test", "active", 1).run();
const OTHER_KEY = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
await db.prepare("INSERT INTO corex_clients (corex_client_id, api_key_hash, display_name, status, created_at) VALUES (?,?,?,?,?)")
    .bind("client-2", await sha256Hex(OTHER_KEY), "Other", "active", 1).run();

const server = createApp(env).listen(0);
const base = `http://127.0.0.1:${server.address().port}`;
const call = (path, { key = API_KEY, method = "GET", body } = {}) =>
    realFetch(base + path, { method, redirect: "manual",
        headers: { ...(key && { Authorization: `Bearer ${key}` }), ...(body && { "Content-Type": "application/json" }) },
        body: body && JSON.stringify(body) });

// --- reference client (what a CoreX instance does) ---
async function newClientKeys() {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    return { priv: kp.privateKey, pub: toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey))) };
}
async function decryptEnvelope(priv, env_, sessionId) {
    const epk = await crypto.subtle.importKey("raw", fromBase64Url(env_.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, priv, 256);
    const hk = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode(sessionId), info: new TextEncoder().encode("corex-token-v2") },
        hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64Url(env_.iv), additionalData: new TextEncoder().encode(sessionId) }, key, fromBase64Url(env_.ct));
    return JSON.parse(new TextDecoder().decode(pt));
}
async function startSession(keys, overrides = {}) {
    const r = await call("/api/v2/auth/sessions", { method: "POST", body: { broker: "upstox", appId: APP_ID, appSecret: APP_SECRET, clientPublicKey: keys.pub, ...overrides } });
    return { r, body: await r.json() };
}
const stateOf = url => new URL(url).searchParams.get("state");
const callback = (state, extra = "code=AUTHCODE1") => call(`/auth/upstox/callback?${extra}&state=${encodeURIComponent(state)}`, { key: null });
const outcome = r => new URL(r.headers.get("location"), base).searchParams.get("status");

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log("  ok -", name); };

await test("happy path: create -> callback -> exchange -> encrypted result -> decrypt", async () => {
    const keys = await newClientKeys();
    const { r, body } = await startSession(keys);
    assert.equal(r.status, 201);
    assert.ok(body.authorizationUrl.startsWith("https://api.upstox.com/v2/login/authorization/dialog"));
    assert.equal(JSON.stringify(body).includes(APP_SECRET), false);

    const state = stateOf(body.authorizationUrl);
    assert.ok(state.startsWith("v2."));
    assert.equal(state.includes(APP_SECRET), false);              // sealed, not just encoded

    let p = await call(`/api/v2/auth/sessions/${body.sessionId}/result`);
    assert.equal(p.status, 202);                                   // pending before callback

    const cb = await callback(state);
    assert.equal(cb.status, 303); assert.equal(outcome(cb), "received");
    assert.equal(upstoxCalls.at(-1).client_secret, APP_SECRET);    // server did the exchange

    p = await call(`/api/v2/auth/sessions/${body.sessionId}/result`);
    assert.equal(p.status, 200);
    const done = await p.json();
    assert.equal(JSON.stringify(done).includes(ACCESS_TOKEN), false); // ciphertext only on the wire to the client
    const token = await decryptEnvelope(keys.priv, done.encrypted, body.sessionId);
    assert.equal(token.accessToken, ACCESS_TOKEN);
    assert.equal(token.tokenType, "Bearer");
    assert.equal(token.profile.userId, "U123");
    assert.equal(JSON.stringify(token).includes("SHOULD-NOT-LEAK"), false);
    assert.ok(new Date(token.expiresAt) > new Date());

    assert.equal((await call(`/api/v2/auth/sessions/${body.sessionId}/result`)).status, 410); // one-time
});

await test("nothing sensitive is ever at rest in D1", async () => {
    const dump = JSON.stringify(db.raw.prepare("SELECT * FROM auth_sessions").all());
    for (const needle of [APP_SECRET, ACCESS_TOKEN, "AUTHCODE1"]) assert.equal(dump.includes(needle), false, needle);
    const row = db.raw.prepare("SELECT result_ciphertext, status FROM auth_sessions WHERE api_version=2 LIMIT 1").get();
    assert.equal(row.result_ciphertext, null);                     // wiped after retrieval
});

await test("replayed callback is rejected and does not hit Upstox again", async () => {
    const keys = await newClientKeys();
    const { body } = await startSession(keys);
    const state = stateOf(body.authorizationUrl);
    assert.equal(outcome(await callback(state)), "received");
    const calls = upstoxCalls.length;
    assert.equal(outcome(await callback(state)), "invalid");
    assert.equal(upstoxCalls.length, calls);
});

await test("tampered / foreign / garbage state is invalid", async () => {
    const keys = await newClientKeys();
    const { body } = await startSession(keys);
    const state = stateOf(body.authorizationUrl);
    const flipped = state.slice(0, -2) + (state.endsWith("AA") ? "BB" : "AA");
    assert.equal(outcome(await callback(flipped)), "invalid");
    assert.equal(outcome(await callback("v2.garbage")), "invalid");
    assert.equal(outcome(await callback("plain-v1-looking-state")), "invalid");
    const otherKeyState = await sealState({ COREX_STATE_KEY: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) },
        { sid: body.sessionId, b: "upstox", exp: 9e9 });
    assert.equal(outcome(await callback(otherKeyState)), "invalid");
});

await test("only the owning client can poll a session", async () => {
    const { body } = await startSession(await newClientKeys());
    assert.equal((await call(`/api/v2/auth/sessions/${body.sessionId}/result`, { key: OTHER_KEY })).status, 404);
    assert.equal((await call(`/api/v2/auth/sessions/${body.sessionId}/result`, { key: null })).status, 401);
});

await test("broker rejection -> failed, no upstream body leaked, code burned", async () => {
    const { body } = await startSession(await newClientKeys());
    upstoxMode = "reject";
    assert.equal(outcome(await callback(stateOf(body.authorizationUrl))), "failed");
    upstoxMode = "ok";
    const p = await call(`/api/v2/auth/sessions/${body.sessionId}/result`);
    assert.equal(p.status, 409);
    const j = await p.json();
    assert.equal(j.error, "exchange_rejected");
    assert.equal(JSON.stringify(j).includes("SUPER-SECRET"), false);
});

await test("user denies at broker (error=access_denied)", async () => {
    const { body } = await startSession(await newClientKeys());
    assert.equal(outcome(await callback(stateOf(body.authorizationUrl), "error=access_denied")), "failed");
    assert.equal((await call(`/api/v2/auth/sessions/${body.sessionId}/result`)).status, 409);
});

await test("input validation: bad key, missing secret, unknown broker", async () => {
    const keys = await newClientKeys();
    assert.equal((await startSession(keys, { clientPublicKey: toBase64Url(new Uint8Array(65).fill(7)) })).r.status, 400);
    assert.equal((await startSession(keys, { clientPublicKey: "nope" })).r.status, 400);
    assert.equal((await startSession(keys, { appSecret: "" })).r.status, 400);
    const unk = await startSession(keys, { broker: "nobroker" });
    assert.equal(unk.r.status, 400); assert.equal(unk.body.error, "unsupported_broker");
    assert.equal((await call("/api/v2/auth/sessions", { method: "POST", key: null, body: {} })).status, 401);
});

await test("400s name the bad field, never echo values, and flag unresolved placeholders", async () => {
    const keys = await newClientKeys();
    const bad = async overrides => (await startSession(keys, overrides)).body;

    let b = await bad({ appId: "{{upstoxApiKey}}" });
    assert.equal(b.field, "appId"); assert.match(b.message, /placeholder/);
    b = await bad({ clientPublicKey: "" });
    assert.equal(b.field, "clientPublicKey");
    b = await bad({ clientPublicKey: "{{clientPublicKey}}" });
    assert.equal(b.field, "clientPublicKey");
    b = await bad({ clientPublicKey: toBase64Url(new Uint8Array(65).fill(7)) });
    assert.equal(b.field, "clientPublicKey"); assert.match(b.message, /keygen/);
    b = await bad({ appSecret: undefined });
    assert.equal(b.field, "appSecret");
    b = await bad({ appId: "short" });
    assert.equal(b.field, "appId");
    b = await bad({ broker: "nobroker" });
    assert.equal(b.error, "unsupported_broker"); assert.match(b.message, /upstox/);

    // Non-JSON content type -> explicit hint instead of a mystery 400.
    const r = await realFetch(base + "/api/v2/auth/sessions", { method: "POST", headers: { Authorization: `Bearer ${API_KEY}`, "Content-Type": "text/plain" }, body: "hello" });
    assert.equal(r.status, 400); assert.match((await r.json()).message, /application\/json/);

    // Surrounding whitespace in the public key (common copy/paste slip) is tolerated.
    const ok = await startSession(keys, { clientPublicKey: ` ${keys.pub}\n` });
    assert.equal(ok.r.status, 201);

    // No submitted secret ever appears in an error body.
    assert.equal(JSON.stringify(await bad({ appId: "x", appSecret: APP_SECRET })).includes(APP_SECRET), false);
});

await test("tools/lib.mjs (used by keygen/decrypt + Postman guide) interoperates with the server", async () => {
    const { generateClientKeys, decryptEnvelope } = await import("../tools/lib.mjs");
    const { publicKey, privateJwk } = await generateClientKeys();
    const { r, body } = await startSession({ pub: publicKey });
    assert.equal(r.status, 201);
    assert.equal(outcome(await callback(stateOf(body.authorizationUrl))), "received");
    const done = await (await call(`/api/v2/auth/sessions/${body.sessionId}/result`)).json();
    const token = await decryptEnvelope({ privateJwk, envelope: done.encrypted, sessionId: body.sessionId });
    assert.equal(token.accessToken, ACCESS_TOKEN);
    await assert.rejects(decryptEnvelope({ privateJwk, envelope: done.encrypted, sessionId: "another-session" }));
});

await test("expired session: callback says expired, poll says expired, cron wipes ciphertext", async () => {
    const keys = await newClientKeys();
    const { body } = await startSession(keys);
    const state = stateOf(body.authorizationUrl);
    assert.equal(outcome(await callback(state)), "received");      // ciphertext now stored
    db.raw.prepare("UPDATE auth_sessions SET created_at = ?, expires_at = ? WHERE session_id = ?").run(Math.floor(Date.now() / 1000) - 400, Math.floor(Date.now() / 1000) - 5, body.sessionId);
    await runMaintenance(env);
    const row = db.raw.prepare("SELECT status, result_ciphertext FROM auth_sessions WHERE session_id=?").get(body.sessionId);
    assert.equal(row.status, "expired"); assert.equal(row.result_ciphertext, null);
    assert.equal((await call(`/api/v2/auth/sessions/${body.sessionId}/result`)).status, 410);

    const { body: b2 } = await startSession(keys);
    db.raw.prepare("UPDATE auth_sessions SET created_at = ?, expires_at = ? WHERE session_id = ?").run(Math.floor(Date.now() / 1000) - 400, Math.floor(Date.now() / 1000) - 5, b2.sessionId);
    const s2 = stateOf(b2.authorizationUrl);
    // sealed exp is still in the future, DB expiry is what blocks the claim:
    assert.equal(outcome(await callback(s2)), "invalid");
});

await test("polling 'pending' is not logged; session creation is", async () => {
    const before = db.raw.prepare("SELECT COUNT(*) n FROM request_logs").get().n;
    const { body } = await startSession(await newClientKeys());
    for (let i = 0; i < 3; i++) await call(`/api/v2/auth/sessions/${body.sessionId}/result`);
    await new Promise(r => setTimeout(r, 50));
    const rows = db.raw.prepare("SELECT path, status_code, broker FROM request_logs ORDER BY rowid").all().slice(before);
    assert.equal(rows.filter(r => r.status_code === 202).length, 0);
    assert.ok(rows.some(r => r.path === "/api/v2/auth/sessions" && r.broker === "upstox"));
});

await test("v1 flow still works unchanged (backward compatible)", async () => {
    const r = await call("/api/v1/auth/sessions", { method: "POST", body: { broker: "upstox", appId: APP_ID } });
    assert.equal(r.status, 201);
    const s = await r.json();
    assert.equal(outcome(await callback(stateOf(s.authorizationUrl), "code=V1CODE")), "received");
    const res = await call(`/api/v1/auth/sessions/${s.sessionId}/result`, { key: s.retrievalSecret });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).authorizationCode, "V1CODE");
});

await test("migration preserved columns/constraints; new broker needs no migration", async () => {
    db.raw.prepare("INSERT INTO auth_sessions (session_id, broker, provider_app_id, api_version, status, created_at, expires_at) VALUES ('x','zerodha','a',2,'pending',1,2)").run();
    assert.throws(() => db.raw.prepare("INSERT INTO auth_sessions (session_id, broker, provider_app_id, status, created_at, expires_at) VALUES ('y','z','a','pending',1,2)").run());
});

await test("v3 OAuth state is sealed and tampering is rejected", async () => {
    const claims = {
        sessionId: "v3-test-session",
        clientId: "client-1",
        broker: "upstox",
        expiresAt: Math.floor(Date.now() / 1000) + 300,
        credentials: {
            appId: APP_ID,
            appSecret: APP_SECRET
        }
    };

    const state = await sealOAuthState(env, claims);

    assert.ok(state.startsWith("v3."));
    assert.equal(state.includes(APP_SECRET), false);

    assert.deepEqual(
        await openOAuthState(env, state),
        claims
    );

    const tampered = state.slice(0, -1) +
        (state.endsWith("A") ? "B" : "A");

    assert.equal(
        await openOAuthState(env, tampered),
        null
    );

    assert.equal(
        await openOAuthState(env, "v3.garbage"),
        null
    );
});

await test("v3 token ciphertext is bound to session and broker", async () => {
    const sessionId = "v3-token-test-session";
    const broker = "upstox";

    const result = {
        token: {
            accessToken: ACCESS_TOKEN,
            tokenType: "Bearer"
        },
        profile: {
            userId: "U123"
        }
    };

    const ciphertext = await sealTokenResult(env, {
        sessionId,
        broker,
        result
    });

    assert.equal(ciphertext.includes(ACCESS_TOKEN), false);

    assert.deepEqual(
        await openTokenResult(env, {
            sessionId,
            broker,
            ciphertext
        }),
        result
    );

    await assert.rejects(
        openTokenResult(env, {
            sessionId: "different-session",
            broker,
            ciphertext
        })
    );

    await assert.rejects(
        openTokenResult(env, {
            sessionId,
            broker: "zerodha",
            ciphertext
        })
    );
});

await test("v3 key derivation rejects missing or invalid master keys", async () => {
    const { derivePurposeKey } = await import(
        "../server/security/keys.js"
    );

    await assert.rejects(
        derivePurposeKey({}, "state"),
        /COREX_MASTER_KEY/
    );

    await assert.rejects(
        derivePurposeKey(
            { COREX_MASTER_KEY: "invalid" },
            "state"
        ),
        /COREX_MASTER_KEY/
    );

    await assert.rejects(
        derivePurposeKey(env, "unknown"),
        /purpose/
    );
});

server.close();
console.log(`\n${passed} tests passed`);
