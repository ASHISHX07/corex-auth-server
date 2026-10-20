import { httpServerHandler } from "cloudflare:node";
import { env } from "cloudflare:workers";
import { createApp } from "./server/app.js";

const port = 3000;
const app = createApp(env);

app.listen(port);

export default httpServerHandler({ port });