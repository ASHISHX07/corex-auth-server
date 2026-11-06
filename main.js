import { httpServerHandler } from "cloudflare:node";
import { env } from "cloudflare:workers";
import { createApp } from "./server/gateway/app.js";
import { runMaintenance } from "./server/services/maintenance.service.js";

const port = 3000;
const app = createApp(env);

app.listen(port);

const http = httpServerHandler({ port });

export default {
    fetch: (...args) => http.fetch(...args),

    // Cron Trigger (see wrangler.jsonc): expire sessions, wipe leftovers, prune old rows.
    async scheduled(_event, workerEnv, ctx) {
        ctx.waitUntil(runMaintenance(workerEnv));
    }
};
