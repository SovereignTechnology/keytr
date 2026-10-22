import type { Event } from 'nostr-tools/core';
/** Options for relay operations */
export interface RelayOptions {
    /** Connection/operation timeout in milliseconds. Defaults to 5000 (5 seconds). */
    timeout?: number;
}
/** Publish a signed keytr event to one or more relays */
export declare function publishKeytrEvent(event: Event, relayUrls: string[], options?: RelayOptions): Promise<void>;
/** Fetch all kind:31777 events for a given pubkey from relays */
export declare function fetchKeytrEvents(pubkey: string, relayUrls: string[], options?: RelayOptions): Promise<Event[]>;
export declare function fetchStoredEvents(pubkey: string, credentialId: Uint8Array, relayUrls: string[], options?: RelayOptions): Promise<Event[]>;
/**
 * Fetch a kind:31777 event by its #d tag (base64url credential ID).
 * Used for KiH mode where we don't have the pubkey upfront.
 * Returns the first matching event, or null if none found.
 */
export declare function fetchKeytrEventByDTag(dTag: string, relayUrls: string[], options?: RelayOptions): Promise<Event | null>;
//# sourceMappingURL=relay.d.ts.map