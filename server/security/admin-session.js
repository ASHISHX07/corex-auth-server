const COOKIE_NAME = "corex_admin_session";
export const SESSION_TTL_SECONDS = 30 * 60;

const encoder = new TextEncoder();

function encodeBase64Url(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

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

function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a[i] ^ b[i];
    }

    return difference === 0;
}

async function importSigningKey(env) {
    if (!env.COREX_ADMIN_SESSION_SECRET) {
        throw new Error(
            "COREX_ADMIN_SESSION_SECRET is not configured."
        );
    }

    return crypto.subtle.importKey(
        "raw",
        encoder.encode(env.COREX_ADMIN_SESSION_SECRET),
        {
            name: "HMAC",
            hash: "SHA-256"
        },
        false,
        ["sign", "verify"]
    );
}

export async function createAdminSessionToken(env, username) {
    const now = Math.floor(Date.now() / 1000);

    const payload = encodeBase64Url(
        encoder.encode(JSON.stringify({
            sub: username,
            iat: now,
            exp: now + SESSION_TTL_SECONDS
        }))
    );

    const key = await importSigningKey(env);

    const signature = new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            key,
            encoder.encode(payload)
        )
    );

    return `${payload}.${encodeBase64Url(signature)}`;
}

export async function verifyAdminSessionToken(env, token) {
    if (typeof token !== "string" || token.length > 4096) {
        return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
        return null;
    }

    try {
        const [payload, suppliedSignature] = parts;
        const key = await importSigningKey(env);

        const validSignature = await crypto.subtle.verify(
            "HMAC",
            key,
            decodeBase64Url(suppliedSignature),
            encoder.encode(payload)
        );

        if (!validSignature) {
            return null;
        }

        const claims = JSON.parse(
            new TextDecoder().decode(
                decodeBase64Url(payload)
            )
        );

        const now = Math.floor(Date.now() / 1000);

        if (
            typeof claims.sub !== "string" ||
            typeof claims.exp !== "number" ||
            claims.exp <= now ||
            typeof claims.iat !== "number" ||
            claims.iat > now + 60
        ) {
            return null;
        }

        return claims;
    } catch {
        return null;
    }
}

export function readAdminSessionCookie(req) {
    const rawCookie = req.get("cookie") || "";

    for (const part of rawCookie.split(";")) {
        const separator = part.indexOf("=");

        if (separator === -1) {
            continue;
        }

        const name = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();

        if (name === COOKIE_NAME) {
            return value;
        }
    }

    return null;
}

function cookieOptions(req, maxAge) {
    const parts = [
        `${COOKIE_NAME}=`,
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        `Max-Age=${maxAge}`
    ];

    if (req?.secure || req?.protocol === "https") {
        parts.push("Secure");
    }

    return parts;
}

export function setAdminSessionCookie(res, token, req) {
    const parts = cookieOptions(req, SESSION_TTL_SECONDS);

    parts[0] = `${COOKIE_NAME}=${token}`;

    res.append("Set-Cookie", parts.join("; "));
}

export function clearAdminSessionCookie(res, req) {
    const parts = cookieOptions(req, 0);

    parts[0] = `${COOKIE_NAME}=`;

    res.append("Set-Cookie", parts.join("; "));
}