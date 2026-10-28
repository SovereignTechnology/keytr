/**
 * Tagged passkey handles from the passkey-held Nostr keys proposal:
 *
 *   "NPK" || 0x01 || 0x01 || parameter set (1) || random (16)   derived, 22 bytes
 *   "NPK" || 0x01 || 0x02 || author public key (32)             stored, 37 bytes
 */
export type HandleClassification = {
    mode: 'derived';
    parameterSet: number;
}
/** `legacy: 'raw-pubkey'` (32 bytes) is only probably stored: confirm it with a record. */
 | {
    mode: 'stored';
    author: string;
    legacy?: 'raw-pubkey';
}
/** Withdrawn keytr v3 key-in-handle, read-only for migration. */
 | {
    mode: 'stored';
    legacy: 'key-in-handle';
} | {
    mode: 'unsupported';
} | {
    mode: 'unknown';
};
/** Classify a WebAuthn userHandle in the order the proposal requires. Never throws. */
export declare function classifyHandle(userHandle: Uint8Array | ArrayBuffer | null | undefined): HandleClassification;
/** The 37-byte tagged stored handle for an author public key (64 lowercase hex chars). */
export declare function buildStoredHandle(author: string): Uint8Array;
//# sourceMappingURL=handle.d.ts.map