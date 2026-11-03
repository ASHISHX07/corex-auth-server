// Usage: node tools/keygen.mjs
// Creates a fresh ECDH keypair for ONE login. Prints the public key (send it to the
// server as `clientPublicKey`) and saves the private key to .corex-client-key.json
// (git-ignored). Run it again for every new login.
import fs from "node:fs";
import { generateClientKeys } from "./lib.mjs";

const { publicKey, privateJwk } = await generateClientKeys();
fs.writeFileSync(".corex-client-key.json", JSON.stringify(privateJwk), { mode: 0o600 });

console.log("Private key saved to .corex-client-key.json (keep it secret, never commit it).\n");
console.log("clientPublicKey (copy this into Postman):\n");
console.log(publicKey);
