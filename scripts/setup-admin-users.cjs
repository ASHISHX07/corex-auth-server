const fs = require("node:fs");
const crypto = require("node:crypto");

const ITERATIONS = 25_000;
const PASSWORD_MIN_LENGTH = 8;
const USERNAME_PATTERN = /^[a-z0-9._-]{3,64}$/;

function ask(promptText, hidden = false) {
    return new Promise((resolve) => {
        const input = process.stdin;

        if (!input.isTTY || typeof input.setRawMode !== "function") {
            throw new Error(
                "Run this script in an interactive terminal."
            );
        }

        let value = "";

        process.stdout.write(promptText);
        input.setRawMode(true);
        input.resume();

        const cleanup = () => {
            input.off("data", onData);
            input.setRawMode(false);
        };

        const onData = (buffer) => {
            for (const ch of buffer.toString("utf8")) {
                if (ch === "\u0003") {
                    cleanup();
                    process.stdout.write("\n");
                    process.exit(130);
                }

                if (ch === "\r" || ch === "\n") {
                    cleanup();
                    process.stdout.write("\n");
                    resolve(value);
                    return;
                }

                if (ch === "\u007f" || ch === "\b") {
                    if (value.length > 0) {
                        value = value.slice(0, -1);

                        if (!hidden) {
                            process.stdout.write("\b \b");
                        }
                    }

                    continue;
                }

                if (ch >= " ") {
                    value += ch;

                    if (!hidden) {
                        process.stdout.write(ch);
                    }
                }
            }
        };

        input.on("data", onData);
    });
}

function makePasswordRecord(username, password) {
    const salt = crypto.randomBytes(16);

    const hash = crypto.pbkdf2Sync(
        password,
        salt,
        ITERATIONS,
        32,
        "sha256"
    );

    return {
        username,
        salt: salt.toString("base64url"),
        hash: hash.toString("base64url")
    };
}

function updateEnvFile(values) {
    const envPath = ".env";

    let contents = fs.existsSync(envPath)
        ? fs.readFileSync(envPath, "utf8")
        : "";

    for (const [key, value] of Object.entries(values)) {
        const line = `${key}=${value}`;
        const pattern = new RegExp(`^${key}=.*$`, "m");

        if (pattern.test(contents)) {
            contents = contents.replace(pattern, line);
        } else {
            contents = contents.replace(/\s*$/, "");
            contents += `${contents ? "\n" : ""}${line}\n`;
        }
    }

    fs.writeFileSync(envPath, contents, {
        encoding: "utf8",
        mode: 0o600
    });
}

async function main() {
    console.log("\nCoreX Admin Account Setup");
    console.log("=========================\n");
    console.log("Exactly two accounts will be configured.");
    console.log("Passwords are hidden while you type.\n");

    const usernames = [];
    const passwords = [];

    for (let i = 1; i <= 2; i++) {
        const username = (
            await ask(`Account ${i} username: `)
        ).trim().toLowerCase();

        if (!USERNAME_PATTERN.test(username)) {
            throw new Error(
                "Username must contain 3-64 lowercase letters, " +
                "numbers, periods, underscores, or hyphens."
            );
        }

        if (usernames.includes(username)) {
            throw new Error("The two usernames must be different.");
        }

        const password = await ask(
            `Account ${i} password (minimum 8 characters): `,
            true
        );

        if (password.length < PASSWORD_MIN_LENGTH) {
            throw new Error(
                "Each password must contain at least 8 characters."
            );
        }

        const confirmation = await ask(
            `Confirm account ${i} password: `,
            true
        );

        if (password !== confirmation) {
            throw new Error("Passwords do not match.");
        }

        usernames.push(username);
        passwords.push(password);
        console.log();
    }

    if (passwords[0] === passwords[1]) {
        throw new Error(
            "Use a different password for each admin account."
        );
    }

    const users = usernames.map((username, index) =>
        makePasswordRecord(username, passwords[index])
    );

    const encodedUsers = Buffer
        .from(JSON.stringify(users), "utf8")
        .toString("base64url");

    const sessionSecret = crypto.randomBytes(32).toString("base64url");

    updateEnvFile({
        COREX_ADMIN_USERS: encodedUsers,
        COREX_ADMIN_SESSION_SECRET: sessionSecret
    });

    console.log("Admin configuration written to .env.");
    console.log("Configured account IDs:");

    for (const username of usernames) {
        console.log(`  - ${username}`);
    }

    console.log("\nPlaintext passwords were not written to .env.");
    console.log("Keep .env private and never commit it to Git.");
}

main().catch((error) => {
    console.error(`\nSetup failed: ${error.message}`);
    process.exitCode = 1;
});