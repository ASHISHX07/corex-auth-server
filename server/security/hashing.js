const encoder = new TextEncoder();

export async function sha256Hex(value) {
    if (typeof value !== "string") {
        throw new TypeError("Expected a string.");
    }

    const digest = await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}