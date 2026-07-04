export class KeytrError extends Error {
    constructor(message) {
        super(message);
        this.name = 'KeytrError';
    }
}
/** Thrown when the authenticator does not support the WebAuthn PRF extension */
export class PrfNotSupportedError extends KeytrError {
    constructor(reason) {
        super(reason ?? 'WebAuthn PRF extension is not supported by this authenticator');
        this.name = 'PrfNotSupportedError';
    }
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
export class KihRegistrationDisabledError extends KeytrError {
    constructor() {
        super('KiH registration was removed in keytr v0.8.0 (the encryption key was interceptable in JS memory). ' +
            'New passkeys use PRF (the default strategy). Existing KiH users can still log in and should call ' +
            'migrateFromKih() to upgrade. KiH decryption will be removed in a future release.');
        this.name = 'KihRegistrationDisabledError';
    }
}
export class EncryptionError extends KeytrError {
    constructor(message) {
        super(message);
        this.name = 'EncryptionError';
    }
}
export class DecryptionError extends KeytrError {
    constructor(message) {
        super(message);
        this.name = 'DecryptionError';
    }
}
export class BlobParseError extends KeytrError {
    constructor(message) {
        super(message);
        this.name = 'BlobParseError';
    }
}
export class WebAuthnError extends KeytrError {
    constructor(message) {
        super(message);
        this.name = 'WebAuthnError';
    }
}
export class RelayError extends KeytrError {
    constructor(message) {
        super(message);
        this.name = 'RelayError';
    }
}
//# sourceMappingURL=errors.js.map