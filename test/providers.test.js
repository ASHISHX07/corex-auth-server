import test from "node:test";
import assert from "node:assert/strict";

import {
    BROKER_IDS,
    getProvider
} from "../server/brokers/registry.js";

import { ProviderError } from "../server/brokers/provider-error.js";

const FIXTURES = {
    upstox: {
        credentials: {
            appId: "APP-ID-123",
            appSecret: "APP-SECRET-123"
        }
    }
};

const REDIRECT_URI =
    "https://auth.example.com/auth/upstox/callback";

for (const brokerId of BROKER_IDS) {
    const provider = getProvider(brokerId);
    const fixture = FIXTURES[brokerId];

    test(`${brokerId}: provider contract`, () => {
        assert.equal(provider.id, brokerId);

        assert.ok(
            Array.isArray(provider.credentialFields)
        );

        assert.equal(
            typeof provider.validateCredentials,
            "function"
        );

        assert.equal(
            typeof provider.buildAuthorizationUrl,
            "function"
        );

        assert.equal(
            typeof provider.parseCallback,
            "function"
        );

        assert.equal(
            typeof provider.exchange,
            "function"
        );

        assert.equal(
            provider.validateCredentials(fixture.credentials),
            null
        );
    });

    test(`${brokerId}: builds a valid authorization URL`, () => {
        const state = "test-sealed-state";

        const authorizationUrl =
            provider.buildAuthorizationUrl({
                credentials: fixture.credentials,
                state,
                redirectUri: REDIRECT_URI
            });

        const url = new URL(authorizationUrl);

        assert.equal(url.searchParams.get("state"), state);

        assert.equal(
            url.searchParams.get("redirect_uri"),
            REDIRECT_URI
        );

        assert.equal(
            url.searchParams.get("response_type"),
            "code"
        );
    });

    test(`${brokerId}: normalizes callback parameters`, () => {
        assert.deepEqual(
            provider.parseCallback({
                code: "authorization-code"
            }),
            { code: "authorization-code" }
        );

        assert.deepEqual(
            provider.parseCallback({
                error: "access_denied"
            }),
            { error: "authorization_denied" }
        );
    });

    test(`${brokerId}: rejects invalid credentials`, () => {
        const invalid = provider.validateCredentials({});

        assert.equal(typeof invalid, "string");
    });
}

test("registry rejects unsupported brokers", () => {
    assert.equal(
        getProvider("unknown"),
        null
    );
});

test("provider errors only accept known error codes", () => {
    const error = new ProviderError("exchange_rejected");

    assert.equal(error.name, "ProviderError");
    assert.equal(error.code, "exchange_rejected");

    assert.throws(
        () => new ProviderError("arbitrary_error"),
        /Invalid provider error code/
    );
});