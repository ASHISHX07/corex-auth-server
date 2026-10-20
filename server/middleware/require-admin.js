function constantTimeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }

    let difference = 0;

    for (let i = 0; i < a.length; i++) {
        difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return difference === 0;
}

export function requireAdmin(env) {
    return (req, res, next) => {
        const expected = env.COREX_ADMIN_API_KEY;
        const authorization = req.get("authorization") ?? "";
        const match = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(
            authorization
        );

        if (typeof expected !== "string" || expected.length !== 43) {
            return res.status(503).json({
                error: "admin_authentication_unavailable"
            });
        }

        if (!match || !constantTimeEqual(match[1], expected)) {
            res.set("WWW-Authenticate", "Bearer");

            return res.status(401).json({
                error: "unauthorized"
            });
        }

        return next();
    };
}