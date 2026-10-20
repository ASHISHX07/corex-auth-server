import { Router } from "express";

const router = Router();

router.get("/", (_req, res) => {
    res.status(200).json({
        message: "success",
        auth_code: "2bk3525kjboubhuob132yb13uo45"
    });
})

export default router;