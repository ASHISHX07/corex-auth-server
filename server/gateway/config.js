function isLocalHost(hostname) {
    const host = hostname
        .replace(/^\[|\]$/g, "")
        .toLowerCase();

    return (
        host === "localhost" ||
        host === "127.0.0.1" ||
        host === "::1"
    );
}

export function getPublicBaseUrl(env) {
    if (typeof env?.PUBLIC_BASE_URL !== "string") {
        throw new Error("PUBLIC_BASE_URL is not configured.");
    }

    let url;

    try {
        url = new URL(env.PUBLIC_BASE_URL);
    } catch {
        throw new Error("PUBLIC_BASE_URL is invalid.");
    }

    const localHttp =
        url.protocol === "http:" &&
        isLocalHost(url.hostname);

    if (
        (url.protocol !== "https:" && !localHttp) ||
        !url.hostname ||
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash
    ) {
        throw new Error(
            "PUBLIC_BASE_URL must be a valid HTTPS origin."
        );
    }

    return url.origin;
}

export function getBrokerRedirectUri(env, brokerId) {
    if (
        typeof brokerId !== "string" ||
        !/^[a-z0-9_-]{2,32}$/.test(brokerId)
    ) {
        throw new Error("Invalid broker identifier.");
    }

    return new URL(
        `/auth/${brokerId}/callback`,
        getPublicBaseUrl(env)
    ).toString();
}