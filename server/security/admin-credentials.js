import { fromBase64Url } from "./encoding.js";

const ITERATIONS = 25_000;
const HASH_LENGTH = 32;
const SALT_LENGTH = 16;

const encoder = new TextEncoder();

function equalBytes(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
    }

    return difference === 0;
}

function getConfiguredUsers(env) {
    if (typeof env?.COREX_ADMIN_USERS !== "string") {
        throw new Error("COREX_ADMIN_USERS is not configured.");
    }

    let users;

    try {
        users = JSON.parse(
            new TextDecoder().decode(
                fromBase64Url(env.COREX_ADMIN_USERS)
            )
        );
    } catch {
        throw new Error("COREX_ADMIN_USERS is invalid.");
    }

    const usernamePattern = /^[a-z0-9._-]{3,64}$/;

    if (
        !Array.isArray(users) ||
        users.length !== 2
    ) {
        throw new Error("Exactly two administrator accounts are required.");
    }

    const normalizedNames = new Set();

    return users.map(user => {
        if (
            typeof user?.username !== "string" ||
            !usernamePattern.test(user.username) ||
            normalizedNames.has(user.username.toLowerCase())
        ) {
            throw new Error("Invalid administrator configuration.");
        }

        normalizedNames.add(user.username.toLowerCase());

        const salt = fromBase64Url(user.salt);
        const hash = fromBase64Url(user.hash);

        if (
            salt.length !== SALT_LENGTH ||
            hash.length !== HASH_LENGTH
        ) {
            throw new Error("Invalid administrator password record.");
        }

        return {
            username: user.username,
            salt,
            hash
        };
    });
}

async function derivePasswordHash(password, salt) {
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const derived = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt,
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        key,
        HASH_LENGTH * 8
    );

    return new Uint8Array(derived);
}

export async function verifyAdminCredentials(
    env,
    username,
    password
) {
    const users = getConfiguredUsers(env);

    if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        password.length > 1024
    ) {
        return null;
    }

    const normalizedUsername = username.trim().toLowerCase();

    const user = users.find(
        entry => entry.username.toLowerCase() === normalizedUsername
    );

    // Perform password derivation even when the username is unknown.
    const salt = user?.salt ?? new Uint8Array(SALT_LENGTH);

    const candidate = await derivePasswordHash(password, salt);

    const expected = user?.hash ?? new Uint8Array(HASH_LENGTH);

    if (!equalBytes(candidate, expected) || !user) {
        return null;
    }

    return {
        username: user.username
    };
}