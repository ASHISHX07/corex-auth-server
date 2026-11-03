// Shared client-side crypto for CoreX Auth Server API v2 (Node >= 18).
import { webcrypto as crypto } from "node:crypto";

const curve = { name: "ECDH", namedCurve: "P-256" };
const utf8 = text => new TextEncoder().encode(text);
const fromB64u = text => new Uint8Array(Buffer.from(text, "base64url"));
const toB64u = bytes => Buffer.from(bytes).toString("base64url");

/** Returns { publicKey (b64url raw point, send this to the server), privateJwk (keep secret) }. */
export async function generateClientKeys() {
    const pair = await crypto.subtle.generateKey(curve, true, ["deriveBits"]);
    return {
        publicKey: toB64u(await crypto.subtle.exportKey("raw", pair.publicKey)),
        privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey)
    };
}

/** Decrypts the `encrypted` envelope from GET /api/v2/auth/sessions/:id/result. */
export async function decryptEnvelope({ privateJwk, envelope, sessionId }) {
    const priv = await crypto.subtle.importKey("jwk", privateJwk, curve, false, ["deriveBits"]);
    const epk = await crypto.subtle.importKey("raw", fromB64u(envelope.epk), curve, false, []);
    const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, priv, 256);
    const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: utf8(sessionId), info: utf8("corex-token-v2") },
        hkdf, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromB64u(envelope.iv), additionalData: utf8(sessionId) },
        key, fromB64u(envelope.ct));
    return JSON.parse(new TextDecoder().decode(plaintext));
}
