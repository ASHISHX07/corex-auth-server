import express from "express";
import { httpServerHandler } from "cloudflare:node";

const app = express();

const options = express.json({
    limit: "16kb",
    strict: true,
    type: "application/json"
});

app.disable("x-powered-by");
app.use(options);


app.get("/", (_req, res) => {
    res.json({
        service: "CoreX Auth Server",
        status: "ok"
    });
});

app.get("/api/health", (_req, res) => {
    res.status(200).json({
        healthy: true,
        timestamp: new Date().toLocaleString()
    });
});

app.get("/api/auth/getAuthCode", (_req, res) => {
    res.status(200).json({
        status: "ok",
        auth_code: "423hjkb563256jhb32546by453gjhk3b425"
    });
});

app.listen(3000);

export default httpServerHandler({ port: 3000 });