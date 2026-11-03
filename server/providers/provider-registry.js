import { createUpstoxProvider } from "./upstox-provider.js";

// To add a broker: write server/providers/<broker>-provider.js that follows the
// contract documented in upstox-provider.js, then register it here. Nothing else
// (routes, DB, callback handling, logging) needs to change.
const providers = {
    upstox: createUpstoxProvider
};

export const BROKER_IDS = Object.freeze(Object.keys(providers));

export function getProvider(env, broker) {
    const factory = Object.hasOwn(providers, broker) ? providers[broker] : null;
    return factory ? factory(env) : null;
}
