import { Router } from "express";
import { requireAdmin } from "../middleware/require-admin.js";
import { revokeCorexClient } from "../services/client-admin.service.js";

export default function createAdminRouter(env) {
    const router = Router();

    router.post(
        "/clients/:clientId/revoke",
        requireAdmin(env),
        async (req, res) => {
            const clientId = req.params.clientId;

            if (
                typeof clientId !== "string" ||
                clientId.length === 0 ||
                clientId.length > 100
            ) {
                return res.status(400).json({
                    error: "invalid_client_id"
                });
            }

            try {
                const result = await revokeCorexClient(env, clientId);

                if (!result) {
                    return res.status(404).json({
                        error: "client_not_found"
                    });
                }

                return res.status(200).json({
                    status: result.status,
                    expiredSessions: result.expiredSessions
                });
            } catch (error) {
                console.error(
                    "Client revocation failed:",
                    error instanceof Error ? error.message : "Unknown error"
                );

                return res.status(500).json({
                    error: "client_revocation_failed"
                });
            }
        }
    );

    return router;
}