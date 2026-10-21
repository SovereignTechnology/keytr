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
/**
 * A passkey keytr refuses after classifying its handle (passkey-held Nostr
 * keys proposal). keytr only reads and writes stored mode, so it never
 * computes a key from these passkeys or turns them into a new identity.
 */
export declare class PasskeyModeError extends KeytrError {
    readonly reason: 'derived' | 'unsupported' | 'unknown' | 'record-not-found';
    constructor(reason: 'derived' | 'unsupported' | 'unknown' | 'record-not-found', detail?: string);
}
//# sourceMappingURL=errors.d.ts.map