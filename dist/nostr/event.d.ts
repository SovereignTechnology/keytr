import { DELETION_EVENT_KIND, type KeytrEventTemplate, type KeytrCredential } from '../types.js';
interface BuildEventOptions {
    credential: KeytrCredential;
    encryptedBlob: string;
    clientName?: string;
    /** AAD version byte. Defaults to KEYTR_VERSION. Strategies may override. */
    version?: number;
}
/** Build an unsigned kind:31777 event template for a passkey-encrypted nsec */
export declare function buildKeytrEvent(options: BuildEventOptions): KeytrEventTemplate;
/** A NIP-09 deletion request event template (before signing) */
export interface DeletionEventTemplate {
    kind: typeof DELETION_EVENT_KIND;
    content: string;
    tags: string[][];
    created_at: number;
}
/**
 * Build an unsigned NIP-09 (kind:5) deletion request for a kind:31777 event.
 *
 * Addressable events are deleted by their coordinate `a` tag
 * (`31777:<pubkey>:<d-tag>`); relays remove all versions up to the deletion's
 * created_at. An optional `e` tag (the specific event id) is included as a
 * belt-and-braces hint for relays that don't index `a` tags.
 *
 * Used by migrateFromKih() to retire the old KiH event after the new PRF
 * event is published.
 */
export declare function buildKeytrDeletionEvent(options: {
    /** Hex-encoded author pubkey (owner of the event being deleted) */
    pubkey: string;
    /** base64url credential ID (the `d` tag) of the event to delete */
    dTag: string;
    /** Optional specific event id to also reference via an `e` tag */
    eventId?: string;
    /** Optional human-readable reason (kind:5 content) */
    reason?: string;
}): DeletionEventTemplate;
export interface ParsedKeytrEvent {
    credentialIdBase64url: string;
    credentialId: Uint8Array;
    rpId: string;
    encryptedBlob: string;
    version: number;
    algorithm: string;
    kdf: string;
    transports: string[];
    clientName?: string;
}
/** Parse a kind:31777 event to extract credential info and encrypted blob */
export declare function parseKeytrEvent(event: {
    kind: number;
    content: string;
    tags: string[][];
}): ParsedKeytrEvent;
export {};
//# sourceMappingURL=event.d.ts.map