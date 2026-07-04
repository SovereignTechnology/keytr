export declare class KeytrError extends Error {
    constructor(message: string);
}
/** Thrown when the authenticator does not support the WebAuthn PRF extension */
export declare class PrfNotSupportedError extends KeytrError {
    constructor(reason?: string);
}
/**
 * Thrown when KiH (Key-in-Handle) registration is attempted.
 *
 * KiH registration was removed in keytr v0.8.0 because the encryption key,
 * stored in the passkey user.id, is interceptable in JavaScript memory.
 * New passkeys use the PRF strategy (the default). Existing KiH users can
 * still log in and should call migrateFromKih() to upgrade; KiH decryption
 * will be removed in a future release.
 */
export declare class KihRegistrationDisabledError extends KeytrError {
    constructor();
}
export declare class EncryptionError extends KeytrError {
    constructor(message: string);
}
export declare class DecryptionError extends KeytrError {
    constructor(message: string);
}
export declare class BlobParseError extends KeytrError {
    constructor(message: string);
}
export declare class WebAuthnError extends KeytrError {
    constructor(message: string);
}
export declare class RelayError extends KeytrError {
    constructor(message: string);
}
//# sourceMappingURL=errors.d.ts.map