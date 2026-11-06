const ERROR_CODES = new Set([
    "authorization_denied",
    "exchange_rejected",
    "provider_unreachable",
    "provider_unavailable",
    "provider_bad_response"
]);

export class ProviderError extends Error {
    constructor(code) {
        if (!ERROR_CODES.has(code)) {
            throw new TypeError("Invalid provider error code.");
        }

        super(code);

        this.name = "ProviderError";
        this.code = code;
    }
}