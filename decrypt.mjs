import { webcrypto as c } from "node:crypto";
import fs from "node:fs";
const [sessionId, file] = process.argv.slice(2);
const { encrypted: e } = JSON.parse(fs.readFileSync(file, "utf8"));
const jwk = JSON.parse(fs.readFileSync("client-private.jwk.json", "utf8"));
const curve = { name: "ECDH", namedCurve: "P-256" };
const b = s => new Uint8Array(Buffer.from(s, "base64url"));
const u = s => new TextEncoder().encode(s);
const priv = await c.subtle.importKey("jwk", jwk, curve, false, ["deriveBits"]);
const epk = await c.subtle.importKey("raw", b(e.epk), curve, false, []);
const shared = await c.subtle.deriveBits({ name: "ECDH", public: epk }, priv, 256);
const hk = await c.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
const key = await c.subtle.deriveKey(
  { name: "HKDF", hash: "SHA-256", salt: u(sessionId), info: u("corex-token-v2") },
  hk, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
const pt = await c.subtle.decrypt({ name: "AES-GCM", iv: b(e.iv), additionalData: u(sessionId) }, key, b(e.ct));
console.log(new TextDecoder().decode(pt));