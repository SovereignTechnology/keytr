export type { KeytrCredential, EncryptedNsecBlob, KeytrEventTemplate, EncryptOptions, DecryptOptions, RegisterOptions, RegisterResult, AuthenticateOptions, DiscoverOptions, DiscoverResult, KeytrBundle, KeyStrategy, KeytrMode, PrfSupportInfo, WebAuthnCapabilities, } from './types.js';
export { KEYTR_VERSION, KEYTR_KIH_VERSION, BLOB_VERSION, KEYTR_EVENT_KIND, DELETION_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS, KIH_KEY_SIZE, KIH_USER_ID_SIZE, KIH_MODE_BYTE, PRF_USER_ID_SIZE, } from './types.js';
export { KeytrError, PrfNotSupportedError, KihRegistrationDisabledError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, } from './errors.js';
export { encryptNsec, buildAad } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
export { checkCapabilities, checkPrfSupport, ensureBrowser } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { authenticatePasskey, kihAuthenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
export { prfRegistrationExtension, prfAuthenticationExtension, extractPrfOutput, isPrfEnabled, } from './webauthn/prf.js';
export { extractKey, detectMode } from './webauthn/kih.js';
export { parseBackupFlags } from './webauthn/flags.js';
export { signalUnknownCredential, signalAllAcceptedCredentialIds, signalCurrentUserDetails, } from './webauthn/signal.js';
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent, buildKeytrDeletionEvent, type ParsedKeytrEvent, type DeletionEventTemplate, } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag, type RelayOptions } from './nostr/relay.js';
export { migrateFromKih, type MigrateOptions, type MigrateResult } from './migrate.js';
import type { RegisterOptions, DiscoverOptions, KeytrBundle, KeyStrategy } from './types.js';
import type { RelayOptions } from './nostr/relay.js';
/**
 * Built-in PRF strategy — the default.
 *
 * The encryption key is the authenticator's PRF output; it is never stored in
 * user.id. Requires a PRF-capable authenticator. AAD/event version = 1.
 */
export declare const prfStrategy: KeyStrategy;
/**
 * Legacy Key-in-Handle (KiH) strategy — DECRYPT-ONLY.
 *
 * Registration is disabled (it throws) because the key stored in user.id is
 * interceptable in JS memory. `authenticate`/`discover` remain so existing KiH
 * credentials can log in and migrate. AAD/event version = 3. Removed in a
 * future release.
 */
export declare const kihStrategy: KeyStrategy;
/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * Uses the PRF strategy by default — a single passkey, key derived by the
 * authenticator (never in user.id).
 */
export declare function setupKeytr(options: Omit<RegisterOptions, 'pubkey'> & {
    clientName?: string;
    strategy?: KeyStrategy;
}): Promise<KeytrBundle & {
    nsecBytes: Uint8Array;
    npub: string;
}>;
/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 */
export declare function addBackupGateway(nsecBytes: Uint8Array, options: Omit<RegisterOptions, 'pubkey'> & {
    clientName?: string;
    strategy?: KeyStrategy;
}): Promise<KeytrBundle>;
/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this user. Each event is dispatched by its
 * `v` tag: v=1 authenticates with PRF, v=3 with the legacy KiH path. The first
 * passkey the authenticator recognises wins. Pass an explicit `strategy` to
 * override dispatch with a custom strategy.
 */
export declare function loginWithKeytr(events: {
    kind: number;
    content: string;
    tags: string[][];
}[], strategy?: KeyStrategy): Promise<{
    nsecBytes: Uint8Array;
    npub: string;
}>;
/** Options for the unified setup flow */
export interface SetupOptions {
    rpId?: string;
    rpName?: string;
    userName: string;
    userDisplayName: string;
    clientName?: string;
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection */
    hints?: string[];
    /** Key derivation strategy. Defaults to prfStrategy (PRF). */
    strategy?: KeyStrategy;
}
/** Result of the unified setup flow */
export interface SetupResult extends KeytrBundle {
    nsecBytes: Uint8Array;
    npub: string;
}
/**
 * Setup: generate nsec, register passkey, encrypt, build event.
 *
 * Uses the PRF strategy by default: the encryption key is derived by the
 * authenticator (never stored in user.id) and the raw pubkey is written to
 * user.id for discoverable login. Single biometric prompt (a follow-up
 * assertion may run on authenticators that only return PRF output on
 * assertion). Throws PrfNotSupportedError when PRF is unavailable.
 */
export declare function setup(options: SetupOptions): Promise<SetupResult>;
/** Result of the discover flow */
export interface DiscoverLoginResult {
    nsecBytes: Uint8Array;
    npub: string;
    pubkey: string;
}
/**
 * Discoverable login: browser shows available passkeys, user picks one,
 * we obtain the key material, fetch the event, and decrypt.
 *
 * Works for both PRF (current) and legacy KiH credentials — the strategy's
 * unified discover detects which. Single biometric prompt for KiH; PRF adds a
 * targeted follow-up assertion. The blob is decrypted with the event's own
 * version tag.
 */
export declare function discover(relays: string[], options?: DiscoverOptions & {
    relayOptions?: RelayOptions;
    strategy?: KeyStrategy;
}): Promise<DiscoverLoginResult>;
//# sourceMappingURL=index.d.ts.map