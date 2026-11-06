/** Thrown by providers. `code` is safe to store/show; never put upstream bodies in it. */
export class ProviderError extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}
