import { Router } from "express";

const router = Router();

router.get("/", (_req, res) => {
    res.json({
        healhy: true,
        timestamp: new Date().toISOString()
    });
});

export default router;