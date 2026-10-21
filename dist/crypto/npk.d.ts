export declare const NPK_STORE_PRF_INPUT: Uint8Array;
export declare const NPK_MAX_PLAINTEXT_BYTES = 65536;
/** Record types; the type byte is the index + 1. */
export declare const NPK_TYPES: readonly ["key", "seed", "vault"];
export type NpkType = (typeof NPK_TYPES)[number];
export declare const NPK_MAX_RECORD_BYTES: number;
/** The values the AAD binds a record to. */
export interface NpkRecordContext {
    type: NpkType;
    rpId: string;
    /** Author public key, 64 lowercase hex chars */
    author: string;
    credentialId: Uint8Array;
}
export declare function npkTypeByte(type: string): number;
export declare function buildNpkAad({ type, rpId, author, credentialId }: NpkRecordContext): Uint8Array;
export declare function deriveNpkKey(keyMaterial: Uint8Array, hkdfSalt: Uint8Array): Uint8Array;
export type EncryptNpkRecordOptions = NpkRecordContext & {
    plaintext: Uint8Array;
    keyMaterial: Uint8Array;
};
/**
 * Encrypt with a given salt and IV. Only for reproducing test vectors:
 * reusing an IV with the same key breaks AES-GCM. Not exported from the package.
 */
export declare function encryptNpkRecordWith(options: EncryptNpkRecordOptions, hkdfSalt: Uint8Array, iv: Uint8Array): Uint8Array;
/** Encrypt a stored record with a fresh random salt and IV. */
export declare function encryptNpkRecord(options: EncryptNpkRecordOptions): Uint8Array;
/** The record type from its public header. Throws on anything that is not a supported npk1 record. */
export declare function npkRecordType(record: Uint8Array): NpkType;
/** Authenticate and decrypt a stored record. The type is read from the header, never guessed from the length. */
export declare function decryptNpkRecord(options: Omit<NpkRecordContext, 'type'> & {
    record: Uint8Array;
    keyMaterial: Uint8Array;
}): {
    type: NpkType;
    plaintext: Uint8Array;
};
//# sourceMappingURL=npk.d.ts.map