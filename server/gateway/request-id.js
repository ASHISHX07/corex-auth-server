export function requestId(req, res, next) {
    const id = crypto.randomUUID();

    req.requestId = id;
    res.set("X-Request-Id", id);

    next();
}