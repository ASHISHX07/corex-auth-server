import { env, waitUntil } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";

import { createApp } from "./server/gateway/app.js";
import { runMaintenance } from "./server/maintenance.js";

const PORT = 3000;

const app = createApp(env, waitUntil);

app.listen(PORT);

const fetchHandler = httpServerHandler({
    port: PORT
});

export default {
    fetch: fetchHandler,

    async scheduled(_controller, scheduledEnv) {
        await runMaintenance(scheduledEnv);
    }
};