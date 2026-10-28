/**
 * Stored-mode passkeys from the passkey-held Nostr keys proposal (npk1).
 * Opt-in next to setup()/discover(), which are unchanged. keytr implements
 * stored mode only and never derives a Nostr key from a PRF output.
 */
import { finalizeEvent } from 'nostr-tools/pure';
import type { DiscoverOptions, KeytrCredential, RegisterOptions } from './types.js';
import { type NpkSecret } from './crypto/npk-secret.js';
import { type RelayOptions } from './nostr/relay.js';
/**
 * Decrypt an npk1 record (from relays, a file or a `largeBlob`) with the PRF
 * output for NPK_STORE_PRF_INPUT, and check that the author is one of the
 * secret's keys (for a seed, its main account) before returning it.
 */
export declare function decryptStoredSecret(options: {
    record: Uint8Array;
    keyMaterial: Uint8Array;
    rpId: string;
    author: string;
    credentialId: Uint8Array;
}): NpkSecret;
/**
 * Register a tagged stored passkey for `secret`, encrypt it as an npk1 record
 * and sign the relay event with the author's key. The author is the key, a
 * seed's main account, or the vault's `default` account (else its first
 * importable one). The secret is checked before the passkey prompt; nothing
 * is published.
 */
export declare function setupStored(secret: NpkSecret, options: Omit<RegisterOptions, 'pubkey'>): Promise<{
    credential: KeytrCredential;
    author: string;
    record: Uint8Array;
    event: ReturnType<typeof finalizeEvent>;
}>;
/** Result of discoverStored(). A keytr v1 record comes back as a `key` secret. */
export interface StoredLoginResult {
    format: 'npk1' | 'keytr-v1';
    secret: NpkSecret;
    author: string;
    credentialId: Uint8Array;
    /** Failed copies that a host must report when another copy recovers. */
    warnings?: string[];
}
/**
 * Discoverable login that classifies the passkey's handle first:
 *
 * - tagged stored: the newest valid npk1 record of the author. If it does not
 *   decrypt, fail; never fall back to an older record.
 * - 32 bytes: the keytr v1 record of that public key (targeted "keytr-v1"
 *   assertion). Without one the passkey is unknown.
 * - derived, unsupported, unknown, legacy key-in-handle: PasskeyModeError,
 *   without querying relays. Key-in-handle passkeys still open with discover().
 */
export declare function discoverStored(relays: string[], options?: DiscoverOptions & {
    relayOptions?: RelayOptions;
}): Promise<StoredLoginResult>;
//# sourceMappingURL=stored.d.ts.map