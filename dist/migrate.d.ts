import type { Event } from 'nostr-tools/core';
import type { DiscoverOptions, KeytrBundle } from './types.js';
import type { RelayOptions } from './nostr/relay.js';
/** Options for migrating a legacy KiH credential to PRF */
export interface MigrateOptions {
    /** Relays to fetch the old event from and publish the new event + deletion to */
    relays: string[];
    /** Gateway rpId of the old credential (and the new one). Defaults to keytr.org. */
    rpId?: string;
    /** Relying Party display name for the new passkey. */
    rpName?: string;
    /** Username metadata for the NEW PRF passkey */
    userName: string;
    /** Display name metadata for the NEW PRF passkey */
    userDisplayName: string;
    /** Optional client name tag on the new event */
    clientName?: string;
    /** WebAuthn ceremony timeout in milliseconds */
    timeout?: number;
    /** WebAuthn Level 3 hints */
    hints?: string[];
    /** Mediation for the discovery (login) ceremony */
    mediation?: DiscoverOptions['mediation'];
    /** Relay operation options (timeout) */
    relayOptions?: RelayOptions;
    /** kind:5 deletion reason (content). */
    deletionReason?: string;
    /** Signal the old KiH credential as unknown after migrating. Defaults to true. */
    signalOldCredential?: boolean;
}
/** Result of a successful KiH → PRF migration */
export interface MigrateResult {
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
    /** The new PRF credential + unsigned template (for app bookkeeping) */
    newBundle: KeytrBundle;
    /** The signed, published kind:31777 (v=1) event */
    newEvent: Event;
    /** The signed kind:5 deletion event (publish attempted) */
    deletionEvent: Event;
    /** false if the kind:5 deletion failed to publish to every relay (non-fatal) */
    deletionPublished: boolean;
    /** Raw credential ID of the retired KiH credential */
    oldCredentialId: Uint8Array;
    /** base64url d-tag of the retired KiH event */
    oldDTag: string;
}
/**
 * Migrate an existing legacy KiH credential to PRF.
 *
 * Flow (with the two load-bearing invariants):
 *   1. Discoverable login with the existing KiH passkey → decrypt the nsec.
 *   2. Verify the decrypted pubkey matches the old event author (mandatory —
 *      d-tag lookups are cross-author).
 *   3. Register a NEW PRF passkey for the same nsec.
 *   4. Encrypt under PRF (v=1), sign, and publish the new event. This must
 *      succeed on at least one relay BEFORE anything is deleted.
 *   5. Publish a NIP-09 kind:5 deletion for the old KiH event (soft-failure:
 *      the new event is already live and KiH decrypt still works this release).
 *   6. Optionally signal the old credential as unknown.
 *
 * The returned nsecBytes is owned by the caller (zero it when done). Throws
 * PrfNotSupportedError (before any deletion) if the authenticator lacks PRF.
 */
export declare function migrateFromKih(options: MigrateOptions): Promise<MigrateResult>;
//# sourceMappingURL=migrate.d.ts.map