import { webcrypto as c } from "node:crypto";
const { COREX_URL, COREX_API_KEY, UPSTOX_API_KEY, UPSTOX_API_SECRET } = process.env;
const b = s => new Uint8Array(Buffer.from(s, "base64url")), u = s => new TextEncoder().encode(s);
const H = { Authorization: `Bearer ${COREX_API_KEY}`, "Content-Type": "application/json" };
const curve = { name: "ECDH", namedCurve: "P-256" };

// 1. fresh keypair, kept in memory only
const kp = await c.subtle.generateKey(curve, true, ["deriveBits"]);
const clientPublicKey = Buffer.from(await c.subtle.exportKey("raw", kp.publicKey)).toString("base64url");

// 2. create session
const r = await fetch(`${COREX_URL}/api/v2/auth/sessions`, { method: "POST", headers: H,
  body: JSON.stringify({ broker: "upstox", appId: UPSTOX_API_KEY, appSecret: UPSTOX_API_SECRET, clientPublicKey }) });
if (r.status !== 201) throw new Error(`create failed ${r.status}: ${await r.text()}`);
const { sessionId, authorizationUrl } = await r.json();
console.log("\nOpen this in your browser and log in (5 min):\n\n" + authorizationUrl + "\n");

// 3. poll until the login finishes
let e;
for (;;) {
  const p = await fetch(`${COREX_URL}/api/v2/auth/sessions/${sessionId}/result`, { headers: H });
  if (p.status === 200) { e = (await p.json()).encrypted; break; }
  if (p.status !== 202) throw new Error(`ended: ${p.status} ${await p.text()}`);
  await new Promise(r => setTimeout(r, 2000));
}

// 4. decrypt with the in-memory private key
const epk = await c.subtle.importKey("raw", b(e.epk), curve, false, []);
const shared = await c.subtle.deriveBits({ name: "ECDH", public: epk }, kp.privateKey, 256);
const hk = await c.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
const key = await c.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: u(sessionId), info: u("corex-token-v2") },
  hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const token = JSON.parse(new TextDecoder().decode(
  await c.subtle.decrypt({ name: "AES-GCM", iv: b(e.iv), additionalData: u(sessionId) }, key, b(e.ct))));
console.log("ACCESS TOKEN:", token.accessToken, "\nExpires:", token.expiresAt);