import { fromBase64Url } from "./encoding.js";

const encoder = new TextEncoder();

const PURPOSES = Object.freeze({
    state: "corex/state/v3",
    token: "corex/token/v3"
});

export async function derivePurposeKey(env, purpose) {
    const info = PURPOSES[purpose];

    if (!info) {
        throw new Error("Unsupported encryption key purpose.");
    }

    const encodedMasterKey = env?.COREX_MASTER_KEY;

    if (typeof encodedMasterKey !== "string") {
        throw new Error("COREX_MASTER_KEY is not configured.");
    }

    let rawMasterKey;

    try {
        rawMasterKey = fromBase64Url(encodedMasterKey);
    } catch {
        throw new Error(
            "COREX_MASTER_KEY must be a base64url-encoded 32-byte key."
        );
    }

    if (rawMasterKey.length !== 32) {
        throw new Error(
            "COREX_MASTER_KEY must be a base64url-encoded 32-byte key."
        );
    }

    let masterKey;

    try {
        masterKey = await crypto.subtle.importKey(
            "raw",
            rawMasterKey,
            "HKDF",
            false,
            ["deriveKey"]
        );
    } finally {
        // Best-effort cleanup of the decoded byte array.
        rawMasterKey.fill(0);
    }

    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: new Uint8Array(0),
            info: encoder.encode(info)
        },
        masterKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}
