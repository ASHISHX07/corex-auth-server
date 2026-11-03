// Usage:  <response body JSON> | node tools/decrypt.mjs <sessionId>
//   PowerShell:  Get-Clipboard | node tools/decrypt.mjs <sessionId>
//   macOS:       pbpaste       | node tools/decrypt.mjs <sessionId>
//   or:          node tools/decrypt.mjs <sessionId> response.json
// Decrypts the one-time result of GET /api/v2/auth/sessions/:id/result using the
// private key written by tools/keygen.mjs.
import fs from "node:fs";
import { decryptEnvelope } from "./lib.mjs";

const [sessionId, file] = process.argv.slice(2);

function fail(message) {
    console.error(`\nERROR: ${message}`);
    process.exit(1);
}

if (!sessionId) fail("Usage: node tools/decrypt.mjs <sessionId> [response.json]  (or pipe the JSON in)");
if (!fs.existsSync(".corex-client-key.json")) fail("No .corex-client-key.json here. Run `node tools/keygen.mjs` from the project root BEFORE creating the session.");

const raw = file ? fs.readFileSync(file, "utf8") : fs.readFileSync(0, "utf8");

let body;
try {
    body = JSON.parse(raw.replace(/^\uFEFF/, ""));
} catch {
    fail("Input is not valid JSON. Paste the WHOLE response body of the 200 response.");
}

if (body.status && body.status !== "completed") {
    fail(`Server said status "${body.status}"${body.error ? ` (${body.error})` : ""}; there is nothing to decrypt.`);
}
if (!body.encrypted) fail('JSON has no "encrypted" field.');

try {
    const token = await decryptEnvelope({
        privateJwk: JSON.parse(fs.readFileSync(".corex-client-key.json", "utf8")),
        envelope: body.encrypted,
        sessionId
    });
    console.log(JSON.stringify(token, null, 2));
} catch {
    fail("Decryption failed. Usual causes: the sessionId is not the one from THIS response, or the key file was regenerated (keygen) after the session was created.");
}
