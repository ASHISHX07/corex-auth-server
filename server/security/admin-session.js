import {
    fromBase64Url,
    toBase64Url
} from "./encoding.js";

const COOKIE_NAME = "corex_admin_session";

export const SESSION_TTL_SECONDS = 30 * 60;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function getSigningKey(env) {
    if (typeof env?.COREX_ADMIN_SESSION_SECRET !== "string") {
        throw new Error("Admin session secret is not configured.");
    }

    const raw = fromBase64Url(env.COREX_ADMIN_SESSION_SECRET);

    if (raw.length !== 32) {
        throw new Error("Invalid admin session secret.");
    }

    return crypto.subtle.importKey(
        "raw",
        raw,
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

    const payload = toBase64Url(
        encoder.encode(JSON.stringify({
            sub: username,
            iat: now,
            exp: now + SESSION_TTL_SECONDS
        }))
    );

    const key = await getSigningKey(env);

    const signature = new Uint8Array(
        await crypto.subtle.sign(
            "HMAC",
            key,
            encoder.encode(payload)
        )
    );

    return `${payload}.${toBase64Url(signature)}`;
}

export async function verifyAdminSessionToken(env, token) {
    if (typeof token !== "string" || token.length > 4096) {
        return null;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
        return null;
    }

    const [payload, signature] = parts;
    const key = await getSigningKey(env);

    try {
        const valid = await crypto.subtle.verify(
            "HMAC",
            key,
            fromBase64Url(signature),
            encoder.encode(payload)
        );

        if (!valid) {
            return null;
        }

        const claims = JSON.parse(
            decoder.decode(fromBase64Url(payload))
        );

        const now = Math.floor(Date.now() / 1000);

        if (
            typeof claims.sub !== "string" ||
            typeof claims.iat !== "number" ||
            typeof claims.exp !== "number" ||
            claims.exp <= now ||
            claims.iat > now + 60 ||
            claims.exp <= claims.iat ||
            claims.exp - claims.iat > SESSION_TTL_SECONDS
        ) {
            return null;
        }

        return claims;
    } catch {
        return null;
    }
}

export function readAdminSessionCookie(req) {
    const raw = req.get("cookie") ?? "";

    for (const part of raw.split(";")) {
        const separator = part.indexOf("=");

        if (separator === -1) continue;

        const name = part.slice(0, separator).trim();

        if (name === COOKIE_NAME) {
            return part.slice(separator + 1).trim();
        }
    }

    return null;
}

function cookieOptions(req, maxAge) {
    const host = (req.get("host") ?? "").toLowerCase();

    const localDevelopment =
        /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host);

    return [
        `${COOKIE_NAME}=`,
        "Path=/",
        "HttpOnly",
        "SameSite=Strict",
        `Max-Age=${maxAge}`,
        ...(!localDevelopment ? ["Secure"] : [])
    ];
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