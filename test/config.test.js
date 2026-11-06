import test from "node:test";
import assert from "node:assert/strict";

import {
    getPublicBaseUrl,
    getBrokerRedirectUri
} from "../server/gateway/config.js";

test("validates and normalizes an HTTPS public base URL", () => {
    assert.equal(
        getPublicBaseUrl({
            PUBLIC_BASE_URL: "https://auth.example.com/"
        }),
        "https://auth.example.com"
    );
});

test("allows HTTP for localhost development", () => {
    assert.equal(
        getPublicBaseUrl({
            PUBLIC_BASE_URL: "http://localhost:8787"
        }),
        "http://localhost:8787"
    );
});

test("rejects missing or invalid public base URLs", () => {
    assert.throws(
        () => getPublicBaseUrl({}),
        /not configured/
    );

    assert.throws(
        () => getPublicBaseUrl({
            PUBLIC_BASE_URL: "not-a-url"
        }),
        /invalid/
    );

    assert.throws(
        () => getPublicBaseUrl({
            PUBLIC_BASE_URL: "http://example.com"
        }),
        /HTTPS origin/
    );

    assert.throws(
        () => getPublicBaseUrl({
            PUBLIC_BASE_URL: "https://example.com/path"
        }),
        /HTTPS origin/
    );
});

test("generates the standard callback URL for any valid broker ID", () => {
    const env = {
        PUBLIC_BASE_URL: "https://auth.example.com"
    };

    assert.equal(
        getBrokerRedirectUri(env, "upstox"),
        "https://auth.example.com/auth/upstox/callback"
    );

    assert.equal(
        getBrokerRedirectUri(env, "zerodha"),
        "https://auth.example.com/auth/zerodha/callback"
    );

    assert.equal(
        getBrokerRedirectUri(env, "fyers"),
        "https://auth.example.com/auth/fyers/callback"
    );
});

test("rejects invalid broker identifiers", () => {
    const env = {
        PUBLIC_BASE_URL: "https://auth.example.com"
    };

    assert.throws(
        () => getBrokerRedirectUri(env, "Upstox")
    );

    assert.throws(
        () => getBrokerRedirectUri(env, "../admin")
    );
});