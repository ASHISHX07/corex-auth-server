import { Router } from "express";

const router = Router();

router.post("/sessions", (req, res) => {
    res.status(201).json({ created: true });
})

router.get("/sessions/:sessionId", (req, res) => {
    res.json({ id: req.params.sessionId });
});

export default router;