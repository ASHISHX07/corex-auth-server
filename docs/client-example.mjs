// Reference client for CoreX Auth Server API v2 (Node >= 18).
//   COREX_URL=https://corex-server.<acct>.workers.dev COREX_API_KEY=... \
//   UPSTOX_API_KEY=... UPSTOX_API_SECRET=... node client-example.mjs
import { webcrypto as crypto } from "node:crypto";

const { COREX_URL, COREX_API_KEY, UPSTOX_API_KEY, UPSTOX_API_SECRET } = process.env;
const b64u = bytes => Buffer.from(bytes).toString("base64url");
const unb64u = text => new Uint8Array(Buffer.from(text, "base64url"));
const headers = { Authorization: `Bearer ${COREX_API_KEY}`, "Content-Type": "application/json" };
const utf8 = text => new TextEncoder().encode(text);

// 1. keypair (private key never leaves this process)
const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
const clientPublicKey = b64u(await crypto.subtle.exportKey("raw", publicKey));

// 2. create the session
const created = await fetch(`${COREX_URL}/api/v2/auth/sessions`, {
    method: "POST", headers,
    body: JSON.stringify({ broker: "upstox", appId: UPSTOX_API_KEY, appSecret: UPSTOX_API_SECRET, clientPublicKey })
});
if (created.status !== 201) throw new Error(`create failed: ${created.status}`);
const { sessionId, authorizationUrl } = await created.json();
console.log("Open this URL and log in:\n", authorizationUrl);

// 3. poll until done
let encrypted;
for (;;) {
    const res = await fetch(`${COREX_URL}/api/v2/auth/sessions/${sessionId}/result`, { headers });
    if (res.status === 200) { ({ encrypted } = await res.json()); break; }
    if (res.status !== 202) throw new Error(`login ended: ${res.status} ${await res.text()}`);
    await new Promise(r => setTimeout(r, 2000));
}

// 4. decrypt
const epk = await crypto.subtle.importKey("raw", unb64u(encrypted.epk), { name: "ECDH", namedCurve: "P-256" }, false, []);
const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: epk }, privateKey, 256);
const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(sessionId), info: utf8("corex-token-v2") },
    hkdf, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(encrypted.iv), additionalData: utf8(sessionId) }, key, unb64u(encrypted.ct));
const token = JSON.parse(new TextDecoder().decode(plaintext));

console.log("Connected. Token expires", token.expiresAt, "for", token.profile.userName ?? token.profile.userId);
// token.accessToken -> use it as `Authorization: Bearer ...` against the Upstox API
