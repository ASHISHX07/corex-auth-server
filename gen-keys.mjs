import { webcrypto as c } from "node:crypto";
import fs from "node:fs";
const kp = await c.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
fs.writeFileSync("client-private.jwk.json", JSON.stringify(await c.subtle.exportKey("jwk", kp.privateKey)));
console.log(Buffer.from(await c.subtle.exportKey("raw", kp.publicKey)).toString("base64url"));