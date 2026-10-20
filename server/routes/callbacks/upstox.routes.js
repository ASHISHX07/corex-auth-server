import { Router } from "express";
import { receiveAuthCode, failAuthSession } from "../../services/auth-sessions.service.js";

const router = Router();

function protectCallbackResponse(res) {
    res.set({
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy":
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    });
}

function completionHtml(status) {
    const pages = {
        received: [
            "Authorization response received",
            "Return to CoreX to finish connecting your account."
        ],
        failed: [
            "Authorization was not completed",
            "Return to CoreX and try again."
        ],
        invalid: [
            "Unable to match this request",
            "The callback is invalid, expired or already used. Return to CoreX and start a new attempt."
        ],
        unavailable: [
            "Service temporarily unavailable",
            "Return to CoreX and try again."
        ]
    };

    const [title, message] = pages[status] ?? pages.invalid;

    return `<!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>${title}</title>
                <style>
                    body { font-family: system-ui, sans-serif; max-width: 560px;
                        margin: 12vh auto; padding: 24px; background: #111; color: #eee; }
                    p { line-height: 1.6; color: #bbb; }
                </style>
            </head>
            <body>
                <h1>${title}</h1>
                <p>${message}</p>
            </body>
            </html>`;
}

function redirectToCompletion(res, status) {
    protectResponse(res);
    return res.redirect(303, `/auth/upstox/complete?status=${status}`);
}

function createUpstoxCallbackRouter(env) {
    const router = Router();

    router.get("/callback", async (req, res) => {
        const { code, state, error } = req.query;

        try {
            if (typeof state !== "string") {
                return redirectToCompletion(res, "invalid");
            }

            if (typeof error === "string" && error.length > 0) {
                const updated = await failAuthSession(env, {
                    broker: "upstox",
                    state
                });

                return redirectToCompletion(
                    res,
                    updated ? "failed" : "invalid"
                );
            }

            if (typeof code !== "string" || code.length === 0) {
                return redirectToCompletion(res, "invalid");
            }

            const accepted = await receiveAuthorizationCode(env, {
                broker: "upstox",
                code,
                state
            });

            return redirectToCompletion(
                res,
                accepted ? "received" : "invalid"
            );
        } catch (err) {
            console.error(
                "Callback processing failed:",
                err instanceof Error ? err.message : "Unknown error"
            );

            return redirectToCompletion(res, "unavailable");
        }
    });

    router.get("/complete", (req, res) => {
        protectResponse(res);
        return res
            .status(200)
            .type("html")
            .send(completionHtml(req.query.status));
    });

    return router;
}

export default createUpstoxCallbackRouter;