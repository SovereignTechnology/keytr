import type { Event } from 'nostr-tools/core';
import type { RegisterOptions, DiscoverOptions, KeytrBundle } from './types.js';
import { type RelayOptions } from './nostr/relay.js';
import { type PayloadContext } from './crypto/payload.js';
type PayloadSelection = Pick<PayloadContext, 'payloadType' | 'schema'>;
/** Register PRF and prepare a typed event. The caller signs and publishes with the author key. */
export declare function setupPayload(payload: Uint8Array, options: RegisterOptions & PayloadSelection & {
    clientName?: string;
}): Promise<KeytrBundle>;
/** Validate the signed event and caller-selected context before starting WebAuthn. */
export declare function unlockPayload(event: Event, expected: Omit<PayloadContext, 'credentialId'>): Promise<Uint8Array>;
/** Discover by userHandle without asking for an npub. Never silently restore an older snapshot. */
export declare function discoverPayload(relays: string[], options: DiscoverOptions & PayloadSelection & {
    relayOptions?: RelayOptions;
}): Promise<{
    payload: Uint8Array;
    pubkey: string;
}>;
export {};
//# sourceMappingURL=payload.d.ts.map