import test from "node:test";
import assert from "node:assert/strict";

import {
    toBase64Url,
    fromBase64Url,
    randomBytes,
    randomBase64Url
} from "../server/security/encoding.js";

import { sha256Hex } from "../server/security/hashing.js";

import { derivePurposeKey } from "../server/security/keys.js";

import {
    sealOAuthState,
    openOAuthState,
    sealTokenResult,
    openTokenResult
} from "../server/security/seal.js";

const env = {
    COREX_MASTER_KEY: toBase64Url(randomBytes(32))
};

test("base64url encoding round-trips", () => {
    const original = randomBytes(32);

    assert.deepEqual(
        fromBase64Url(toBase64Url(original)),
        original
    );

    assert.throws(() => fromBase64Url("invalid!"));
});

test("random values are generated independently", () => {
    assert.notEqual(
        randomBase64Url(),
        randomBase64Url()
    );

    assert.equal(randomBytes(32).length, 32);
});

test("SHA-256 hashing produces the expected digest", async () => {
    assert.equal(
        await sha256Hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
});

test("purpose key derivation accepts a valid master key", async () => {
    const stateKey = await derivePurposeKey(env, "state");
    const tokenKey = await derivePurposeKey(env, "token");

    assert.ok(stateKey);
    assert.ok(tokenKey);
});

test("purpose key derivation rejects invalid configuration", async () => {
    await assert.rejects(
        derivePurposeKey({}, "state"),
        /not configured/
    );

    await assert.rejects(
        derivePurposeKey({
            COREX_MASTER_KEY: "invalid!"
        }, "state"),
        /32-byte key/
    );

    await assert.rejects(
        derivePurposeKey({
            COREX_MASTER_KEY: toBase64Url(randomBytes(16))
        }, "state"),
        /32-byte key/
    );

    await assert.rejects(
        derivePurposeKey(env, "unknown"),
        /Unsupported/
    );
});

test("OAuth state can be sealed and opened", async () => {
    const claims = {
        sessionId: "session-123",
        clientId: "client-123",
        broker: "upstox",
        expiresAt: Math.floor(Date.now() / 1000) + 300,
        credentials: {
            appId: "APP-ID-123",
            appSecret: "SECRET-VALUE"
        }
    };

    const state = await sealOAuthState(env, claims);

    assert.ok(state.startsWith("v3."));
    assert.ok(!state.includes("SECRET-VALUE"));

    assert.deepEqual(
        await openOAuthState(env, state),
        claims
    );
});

test("invalid and tampered OAuth state is rejected", async () => {
    const state = await sealOAuthState(env, {
        sessionId: "session-123",
        clientId: "client-123",
        broker: "upstox",
        expiresAt: 9999999999,
        credentials: {
            appId: "APP-ID"
        }
    });

    const tampered = state.slice(0, -1) +
        (state.endsWith("A") ? "B" : "A");

    assert.equal(await openOAuthState(env, tampered), null);
    assert.equal(await openOAuthState(env, "v3.invalid"), null);
    assert.equal(await openOAuthState(env, "invalid"), null);
});

test("token ciphertext is bound to its session and broker", async () => {
    const context = {
        sessionId: "session-123",
        broker: "upstox"
    };

    const result = {
        token: {
            accessToken: "SECRET-ACCESS-TOKEN",
            tokenType: "Bearer"
        }
    };

    const ciphertext = await sealTokenResult(env, {
        ...context,
        result
    });

    assert.ok(!ciphertext.includes("SECRET-ACCESS-TOKEN"));

    assert.deepEqual(
        await openTokenResult(env, {
            ...context,
            ciphertext
        }),
        result
    );

    await assert.rejects(
        openTokenResult(env, {
            ...context,
            sessionId: "another-session",
            ciphertext
        }),
        /decryption failed/
    );

    await assert.rejects(
        openTokenResult(env, {
            ...context,
            broker: "zerodha",
            ciphertext
        }),
        /decryption failed/
    );
});