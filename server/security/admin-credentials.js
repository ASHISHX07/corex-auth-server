import { pbkdf2 } from "node:crypto";
import { Buffer } from "node:buffer";

const ITERATIONS = 25_000;
const HASH_LENGTH = 32;

const encoder = new TextEncoder();

function decodeBase64Url(value) {
    const standard = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const padded = standard + "=".repeat(
        (4 - (standard.length % 4)) % 4
    );

    const binary = atob(padded);

    return Uint8Array.from(
        binary,
        (character) => character.charCodeAt(0)
    );
}

function equalBytes(a, b) {
    let difference = a.length ^ b.length;
    const length = Math.max(a.length, b.length);

    for (let i = 0; i < length; i++) {
        difference |=
            (a[i % (a.length || 1)] ?? 0) ^
            (b[i % (b.length || 1)] ?? 0);
    }

    return difference === 0;
}

function derivePasswordHash(password, salt) {
    return new Promise((resolve, reject) => {
        pbkdf2(
            password,
            Buffer.from(salt),
            ITERATIONS,
            HASH_LENGTH,
            "sha256",
            (error, derivedKey) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(new Uint8Array(derivedKey));
            }
        );
    });
}

function getConfiguredUsers(env) {
    if (!env.COREX_ADMIN_USERS) {
        throw new Error("COREX_ADMIN_USERS is not configured.");
    }

    let users;

    try {
        const decoded = new TextDecoder().decode(
            decodeBase64Url(env.COREX_ADMIN_USERS)
        );

        users = JSON.parse(decoded);
    } catch {
        throw new Error("COREX_ADMIN_USERS is invalid.");
    }

    if (
        !Array.isArray(users) ||
        users.length !== 2 ||
        users.some((user) =>
            typeof user.username !== "string" ||
            typeof user.salt !== "string" ||
            typeof user.hash !== "string"
        )
    ) {
        throw new Error(
            "COREX_ADMIN_USERS must contain exactly two valid accounts."
        );
    }

    return users;
}

export async function verifyAdminCredentials(
    env,
    username,
    password
) {
    const users = getConfiguredUsers(env);

    const normalizedUsername = String(username ?? "")
        .trim()
        .toLowerCase();

    const suppliedPassword = String(password ?? "");

    const user = users.find(
        (entry) =>
            entry.username.toLowerCase() === normalizedUsername
    );

    // Unknown users still require a password-hash computation.
    const salt = user
        ? decodeBase64Url(user.salt)
        : new Uint8Array(16);

    const candidateHash = await derivePasswordHash(
        suppliedPassword,
        salt
    );

    const expectedHash = user
        ? decodeBase64Url(user.hash)
        : new Uint8Array(HASH_LENGTH);

    if (
        expectedHash.length !== HASH_LENGTH ||
        candidateHash.length !== HASH_LENGTH
    ) {
        return null;
    }

    if (!equalBytes(candidateHash, expectedHash) || !user) {
        return null;
    }

    return {
        username: user.username
    };
}