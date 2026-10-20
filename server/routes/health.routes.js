import { Router } from "express";

const router = Router();

router.get("/", (_req, res) => {
    res.json({
        healthy: true,
        timestamp: new Date().toISOString()
    });
});

export default router;