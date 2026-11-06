const API_PATH = /^\/api(?:\/|$)/;

export function sendApiError(
    res,
    status,
    error,
    message,
    field
) {
    const body = { error, message };

    if (typeof field === "string" && field.length > 0) {
        body.field = field;
    }

    return res.status(status).json(body);
}

export function notFoundHandler(req, res, next) {
    if (API_PATH.test(req.path)) {
        return sendApiError(
            res,
            404,
            "not_found",
            "The requested API endpoint was not found."
        );
    }

    return res
        .status(404)
        .type("text/plain")
        .send("Not found.");
}

export function apiErrorHandler(error, req, res, next) {
    if (res.headersSent) {
        return next(error);
    }

    if (!API_PATH.test(req.path)) {
        return next(error);
    }

    if (error?.type === "entity.parse.failed") {
        return sendApiError(
            res,
            400,
            "invalid_json",
            "The request body contains invalid JSON."
        );
    }

    if (
        error?.type === "entity.too.large" ||
        error?.status === 413
    ) {
        return sendApiError(
            res,
            413,
            "payload_too_large",
            "The request body exceeds the allowed size."
        );
    }

    if (
        error?.type === "charset.unsupported" ||
        error?.type === "encoding.unsupported"
    ) {
        return sendApiError(
            res,
            415,
            "unsupported_media_type",
            "The request uses an unsupported encoding."
        );
    }

    // Never log request bodies, headers, credentials or provider responses.
    console.error("API request failed", {
        requestId: req.requestId,
        error: "internal_error"
    });

    return sendApiError(
        res,
        500,
        "internal_error",
        "An unexpected server error occurred."
    );
}