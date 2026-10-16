import { httpServerHandler } from "cloudflare:node";
import { env } from "cloudflare:workers";
import { createApp } from "./server/app.js";

const PORT = 3000;

const app = createApp(env);

app.listen(3000);

export default httpServerHandler({ PORT });