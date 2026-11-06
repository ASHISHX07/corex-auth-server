import { env } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";

import { createApp } from "./server/gateway/app.js";

const PORT = 3000;

const app = createApp(env);

app.listen(PORT);

export default httpServerHandler({
    port: PORT
});