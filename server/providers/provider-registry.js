import { createUpstoxProvider } from "./upstox-provider.js";

const providers = {
    upstox: createUpstoxProvider

    // Add zerodha and fyers here when implemented.
};

export function getProvider(env, broker) {
    const factory = providers[broker];

    if (!factory) {
        return null;
    }

    return factory(env);
}