// Operator tool: register a CoreX client.
//   node scripts/create-client.cjs "Display name"            (dry run: prints key + SQL)
//   node scripts/create-client.cjs "Display name" --remote   (inserts into production D1)
//   node scripts/create-client.cjs "Display name" --local    (inserts into local D1)
// The API key is shown ONCE. Only its SHA-256 hash is stored.
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const args = process.argv.slice(2);
const target = args.includes("--remote") ? "--remote" : args.includes("--local") ? "--local" : null;
const name = args.filter(a => !a.startsWith("--")).join(" ").trim();

if (!name || name.length > 80 || /[\u0000-\u001f]/.test(name)) {
    console.error('Usage: node scripts/create-client.cjs "Display name (max 80 chars)" [--remote|--local]');
    process.exit(1);
}

const apiKey = `cx_${crypto.randomBytes(32).toString("base64url")}`;
const hash = crypto
    .createHash("sha256")
    .update(apiKey)
    .digest("hex");

const keyHint = apiKey.slice(-4);
const scopes = '["auth"]';
const createdBy = "cli";

const clientId = crypto.randomUUID();
const auditId = crypto.randomUUID();

const safeName = name.replace(/'/g, "''");

const clientInsert = `
    INSERT INTO corex_clients (
        corex_client_id,
        api_key_hash,
        key_hint,
        display_name,
        scopes,
        status,
        created_at,
        created_by
    )
    VALUES (
        '${clientId}',
        '${hash}',
        '${keyHint}',
        '${safeName}',
        '${scopes}',
        'active',
        strftime('%s', 'now'),
        '${createdBy}'
    );
`;

const auditInsert = `
    INSERT INTO admin_audit (
        id,
        at,
        actor,
        action,
        target_type,
        target_id
    )
    VALUES (
        '${auditId}',
        strftime('%s', 'now'),
        '${createdBy}',
        'client.create',
        'client',
        '${clientId}'
    );
`;

const sql = `${clientInsert}\n${auditInsert}`;
if (target) {
    const file = path.join(os.tmpdir(), `corex-client-${clientId}.sql`);
    fs.writeFileSync(file, sql, { mode: 0o600 });
    const result = spawnSync(
        "npx", ["wrangler", "d1", "execute", "corex-db", target, "--file", file],
        { stdio: "inherit", shell: process.platform === "win32" }
    );
    fs.rmSync(file, { force: true });
    if (result.status !== 0) {
        console.error("\nInsert failed; no client was registered. The key below is NOT valid.");
        process.exit(result.status ?? 1);
    }
} else {
    console.log("DRY RUN (nothing written). SQL that would be executed:\n\n" + sql + "\n");
}

console.log(`Client ID : ${clientId}`);
console.log(`Name      : ${name}`);
console.log(`API key   : ${apiKey}`);
console.log("\nGive the API key to the client over a private channel. It cannot be shown again.");
