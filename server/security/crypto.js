const encoder = new TextEncoder();
const decoder = new TextDecoder();

const STATE_PREFIX = "v2.";
const STATE_AAD = encoder.encode("corex:state:v2");
const TOKEN_INFO = encoder.encode("corex-token-v2");
const ENVELOPE_ALG = "ECDH-P256+HKDF-SHA256+AES-256-GCM";

/* ---------- encoding helpers ---------- */

export function toBase64Url(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function fromBase64Url(value) {
    if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) {
        throw new Error("Invalid base64url");
    }
    const padded = value.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(value.length / 4) * 4, "=");
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

export function randomBase64Url(byteLength = 32) {
    return toBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Hex(value) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

/* ---------- sealed state (stateless; nothing is stored server-side) ---------- */

const stateKeyCache = new Map();

async function getStateKey(env) {
    const raw = env.COREX_STATE_KEY;
    if (typeof raw !== "string") throw new Error("COREX_STATE_KEY is not configured");

    let key = stateKeyCache.get(raw);
    if (!key) {
        const bytes = fromBase64Url(raw);
        if (bytes.length !== 32) throw new Error("COREX_STATE_KEY must be 32 bytes");
        key = await crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
        stateKeyCache.set(raw, key);
    }
    return key;
}

export function isSealedState(value) {
    return typeof value === "string" && value.startsWith(STATE_PREFIX);
}

export async function sealState(env, payload) {
    const key = await getStateKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: STATE_AAD },
        key,
        encoder.encode(JSON.stringify(payload))
    ));
    const out = new Uint8Array(iv.length + ciphertext.length);
    out.set(iv);
    out.set(ciphertext, iv.length);
    return STATE_PREFIX + toBase64Url(out);
}

/** Returns the payload, or null if the state is malformed / tampered with. */
export async function openState(env, state) {
    try {
        if (!isSealedState(state) || state.length > 4096) return null;
        const bytes = fromBase64Url(state.slice(STATE_PREFIX.length));
        if (bytes.length < 12 + 16) return null;

        const key = await getStateKey(env);
        const plaintext = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: STATE_AAD },
            key,
            bytes.slice(12)
        );
        return JSON.parse(decoder.decode(plaintext));
    } catch {
        return null;
    }
}

/* ---------- end-to-end result encryption (server -> client) ---------- */

const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };

/** Throws unless value is a valid uncompressed P-256 point (base64url, 65 bytes). */
export async function importClientPublicKey(value) {
    const bytes = fromBase64Url(value);
    if (bytes.length !== 65 || bytes[0] !== 4) throw new Error("Invalid public key");
    return crypto.subtle.importKey("raw", bytes, ECDH_P256, false, []);
}

/**
 * Encrypts `payload` so only the holder of the client's private key can read
 * it. A fresh ephemeral key is used per call; the server keeps nothing.
 * `context` (the session id) is bound in as HKDF salt and AES-GCM AAD.
 */
export async function encryptForClient(clientPublicKey, payload, context) {
    const clientKey = await importClientPublicKey(clientPublicKey);
    const ephemeral = await crypto.subtle.generateKey(ECDH_P256, true, ["deriveBits"]);

    const shared = await crypto.subtle.deriveBits(
        { name: "ECDH", public: clientKey }, ephemeral.privateKey, 256
    );
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: encoder.encode(context), info: TOKEN_INFO },
        hkdf,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: encoder.encode(context) },
        aesKey,
        encoder.encode(JSON.stringify(payload))
    ));

    return {
        v: 2,
        alg: ENVELOPE_ALG,
        epk: toBase64Url(new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey))),
        iv: toBase64Url(iv),
        ct: toBase64Url(ciphertext)
    };
}
