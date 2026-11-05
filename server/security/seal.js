import { toBase64Url, fromBase64Url, randomBytes } from "./encoding.js";
import { derivePurposeKey } from "./keys.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const STATE_PREFIX = "v3.";
const STATE_AAD = encoder.encode("corex-state-v3");

const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_STATE_LENGTH = 4096;

function isRecord(value) {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
}

function isValidStateClaims(value) {
    return (
        isRecord(value) &&
        typeof value.sessionId === "string" &&
        value.sessionId.length > 0 &&
        typeof value.clientId === "string" &&
        value.clientId.length > 0 &&
        typeof value.broker === "string" &&
        /^[a-z0-9_-]{2,32}$/.test(value.broker) &&
        Number.isSafeInteger(value.expiresAt) &&
        isRecord(value.credentials)
    );
}

function tokenAdditionalData(sessionId, broker) {
    if (
        typeof sessionId !== "string" ||
        sessionId.length === 0 ||
        sessionId.length > 128 ||
        typeof broker !== "string" ||
        !/^[a-z0-9_-]{2,32}$/.test(broker)
    ) {
        throw new Error("Invalid token encryption context.");
    }

    return encoder.encode(
        `corex-token-v3:${sessionId}:${broker}`
    );
}

function combine(iv, ciphertext) {
    const output = new Uint8Array(iv.length + ciphertext.length);

    output.set(iv);
    output.set(ciphertext, iv.length);

    return output;
}

/* ---------- OAuth state ---------- */

export async function sealOAuthState(env, claims) {
    if (!isValidStateClaims(claims)) {
        throw new Error("Invalid OAuth state claims.");
    }

    const key = await derivePurposeKey(env, "state");
    const iv = randomBytes(IV_LENGTH);

    const plaintext = encoder.encode(
        JSON.stringify(claims)
    );

    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: STATE_AAD
            },
            key,
            plaintext
        )
    );

    const state = STATE_PREFIX + toBase64Url(
        combine(iv, ciphertext)
    );

    if (state.length > MAX_STATE_LENGTH) {
        throw new Error("OAuth state exceeds the allowed size.");
    }

    return state;
}

export async function openOAuthState(env, state) {
    if (
        typeof state !== "string" ||
        !state.startsWith(STATE_PREFIX) ||
        state.length > MAX_STATE_LENGTH
    ) {
        return null;
    }

    let bytes;

    try {
        bytes = fromBase64Url(
            state.slice(STATE_PREFIX.length)
        );
    } catch {
        return null;
    }

    if (bytes.length < IV_LENGTH + TAG_LENGTH) {
        return null;
    }

    // Keep configuration errors visible. Only malformed/tampered
    // ciphertext should be converted into an invalid state.
    const key = await derivePurposeKey(env, "state");

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: bytes.slice(0, IV_LENGTH),
                additionalData: STATE_AAD
            },
            key,
            bytes.slice(IV_LENGTH)
        );

        const claims = JSON.parse(
            decoder.decode(plaintext)
        );

        return isValidStateClaims(claims) ? claims : null;
    } catch {
        return null;
    }
}

/* ---------- Token result at rest ---------- */

export async function sealTokenResult(
    env,
    { sessionId, broker, result }
) {
    if (!isRecord(result)) {
        throw new Error("Invalid token result.");
    }

    const key = await derivePurposeKey(env, "token");
    const iv = randomBytes(IV_LENGTH);
    const aad = tokenAdditionalData(sessionId, broker);

    const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: aad
            },
            key,
            encoder.encode(JSON.stringify(result))
        )
    );

    // Stored in D1 as base64url(IV || ciphertext || GCM tag).
    return toBase64Url(combine(iv, ciphertext));
}

export async function openTokenResult(
    env,
    { sessionId, broker, ciphertext }
) {
    if (
        typeof ciphertext !== "string" ||
        ciphertext.length > 65536
    ) {
        throw new Error("Invalid stored token result.");
    }

    let bytes;

    try {
        bytes = fromBase64Url(ciphertext);
    } catch {
        throw new Error("Invalid stored token result.");
    }

    if (bytes.length < IV_LENGTH + TAG_LENGTH) {
        throw new Error("Invalid stored token result.");
    }

    const key = await derivePurposeKey(env, "token");
    const aad = tokenAdditionalData(sessionId, broker);

    try {
        const plaintext = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: bytes.slice(0, IV_LENGTH),
                additionalData: aad
            },
            key,
            bytes.slice(IV_LENGTH)
        );

        const result = JSON.parse(
            decoder.decode(plaintext)
        );

        if (!isRecord(result)) {
            throw new Error();
        }

        return result;
    } catch {
        throw new Error("Token result decryption failed.");
    }
}
