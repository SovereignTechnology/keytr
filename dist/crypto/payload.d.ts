/** Draft typed-payload protocol. Does not alter v1 nsec or legacy v3. */
export declare const PAYLOAD_VERSION = 4;
export declare const MAX_PAYLOAD_BYTES: number;
export type PayloadType = 'seed' | 'vault';
export interface PayloadContext {
    credentialId: Uint8Array;
    /** Event author and discoverable credential's userHandle. */
    pubkey: string;
    rpId: string;
    payloadType: PayloadType;
    /** Application-owned, versioned serialization identifier. */
    schema: string;
}
export type EncryptPayloadOptions = PayloadContext & {
    keyMaterial: Uint8Array;
    payload: Uint8Array;
};
export type DecryptPayloadOptions = PayloadContext & {
    keyMaterial: Uint8Array;
    encryptedBlob: string;
};
export declare function validatePayloadContext(context: PayloadContext): void;
/** Strictly bound content before allocating its decoded buffer. */
export declare function decodePayloadBlob(content: string): Uint8Array;
/** Encrypt opaque application bytes; callers own schema validation and plaintext cleanup. */
export declare function encryptPayload(options: EncryptPayloadOptions): string;
/** Authenticate the full context before returning any plaintext bytes. */
export declare function decryptPayload(options: DecryptPayloadOptions): Uint8Array;
//# sourceMappingURL=payload.d.ts.map