export function toBase64Url(bytes) {
    if (!(bytes instanceof Uint8Array)) {
        throw new TypeError("Expected Uint8Array.");
    }

    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

export function fromBase64Url(value) {
    if (
        typeof value !== "string" ||
        value.length === 0 ||
        !/^[A-Za-z0-9_-]+$/.test(value) ||
        value.length % 4 === 1
    ) {
        throw new Error("Invalid base64url value.");
    }

    const standard = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const padded = standard.padEnd(
        Math.ceil(standard.length / 4) * 4,
        "="
    );

    let binary;

    try {
        binary = atob(padded);
    } catch {
        throw new Error("Invalid base64url value.");
    }

    const bytes = Uint8Array.from(
        binary,
        character => character.charCodeAt(0)
    );

    if (toBase64Url(bytes) !== value) {
        throw new Error("Invalid base64url value.");
    }

    return bytes;
}

export function randomBytes(byteLength = 32) {
    if (
        !Number.isSafeInteger(byteLength) ||
        byteLength < 1 ||
        byteLength > 65536
    ) {
        throw new RangeError("Invalid random byte length.");
    }

    return crypto.getRandomValues(
        new Uint8Array(byteLength)
    );
}

export function randomBase64Url(byteLength = 32) {
    return toBase64Url(randomBytes(byteLength));
}