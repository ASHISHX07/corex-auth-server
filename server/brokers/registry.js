import { upstoxProvider } from "./upstox.js";

const providers = new Map([
    [upstoxProvider.id, upstoxProvider]
]);

export const BROKER_IDS = Object.freeze([
    ...providers.keys()
]);

export function getProvider(brokerId) {
    return providers.get(brokerId) ?? null;
}