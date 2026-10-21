export { KEYTR_VERSION, KEYTR_KIH_VERSION, BLOB_VERSION, KEYTR_EVENT_KIND, DELETION_EVENT_KIND, DEFAULT_RP_ID, DEFAULT_RP_NAME, KEYTR_GATEWAYS, KIH_KEY_SIZE, KIH_USER_ID_SIZE, KIH_MODE_BYTE, PRF_USER_ID_SIZE, } from './types.js';
// Errors
export { KeytrError, PrfNotSupportedError, KihRegistrationDisabledError, EncryptionError, DecryptionError, BlobParseError, WebAuthnError, RelayError, PasskeyModeError, } from './errors.js';
// Crypto
export { encryptNsec, buildAad } from './crypto/encrypt.js';
export { decryptNsec } from './crypto/decrypt.js';
export { deriveKey } from './crypto/kdf.js';
export { serializeBlob, deserializeBlob } from './crypto/blob.js';
// WebAuthn
export { checkCapabilities, checkPrfSupport, ensureBrowser } from './webauthn/support.js';
export { registerPasskey } from './webauthn/register.js';
export { authenticatePasskey, kihAuthenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
export { prfRegistrationExtension, prfAuthenticationExtension, extractPrfOutput, isPrfEnabled, } from './webauthn/prf.js';
export { extractKey, detectMode } from './webauthn/kih.js';
export { parseBackupFlags } from './webauthn/flags.js';
export { signalUnknownCredential, signalAllAcceptedCredentialIds, signalCurrentUserDetails, } from './webauthn/signal.js';
// Nostr
export { generateNsec, nsecToPublicKey, encodeNsec, decodeNsec, encodeNpub, decodeNpub, nsecToNpub, nsecToHexPubkey, } from './nostr/keys.js';
export { buildKeytrEvent, parseKeytrEvent, buildKeytrDeletionEvent, } from './nostr/event.js';
export { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag } from './nostr/relay.js';
// Migration (legacy KiH → PRF)
export { migrateFromKih } from './migrate.js';
import { DEFAULT_RP_ID, KEYTR_VERSION, KEYTR_KIH_VERSION } from './types.js';
import { WebAuthnError, KeytrError, KihRegistrationDisabledError, PrfNotSupportedError } from './errors.js';
import { registerPasskey } from './webauthn/register.js';
import { authenticatePasskey, kihAuthenticatePasskey } from './webauthn/authenticate.js';
import { discoverPasskey as _discoverPasskey } from './webauthn/authenticate.js';
import { checkPrfSupport as _checkPrfSupport } from './webauthn/support.js';
import { encryptNsec as _encryptNsec } from './crypto/encrypt.js';
import { decryptNsec as _decryptNsec } from './crypto/decrypt.js';
import { buildKeytrEvent as _buildEvent } from './nostr/event.js';
import { parseKeytrEvent as _parseEvent } from './nostr/event.js';
import { generateNsec as _generateNsec, nsecToNpub as _nsecToNpub, nsecToHexPubkey as _nsecToHexPubkey } from './nostr/keys.js';
import { fetchKeytrEvents as _fetchByPubkey, fetchKeytrEventByDTag as _fetchByDTag } from './nostr/relay.js';
import { base64url } from '@scure/base';
import { safeZero } from './crypto/builtins.js';
/**
 * Built-in PRF strategy — the default.
 *
 * The encryption key is the authenticator's PRF output; it is never stored in
 * user.id. Requires a PRF-capable authenticator. AAD/event version = 1.
 */
export const prfStrategy = {
    version: KEYTR_VERSION,
    register: registerPasskey,
    authenticate: authenticatePasskey,
    discover: _discoverPasskey,
};
/**
 * Legacy Key-in-Handle (KiH) strategy — DECRYPT-ONLY.
 *
 * Registration is disabled (it throws) because the key stored in user.id is
 * interceptable in JS memory. `authenticate`/`discover` remain so existing KiH
 * credentials can log in and migrate. AAD/event version = 3. Removed in a
 * future release.
 */
export const kihStrategy = {
    version: KEYTR_KIH_VERSION,
    register: async () => {
        throw new KihRegistrationDisabledError();
    },
    authenticate: kihAuthenticatePasskey,
    discover: _discoverPasskey,
};
/** Throw early if the browser/authenticator definitively lacks PRF support. */
async function _assertPrfSupported() {
    const support = await _checkPrfSupport();
    if (!support.supported) {
        throw new PrfNotSupportedError(support.reason ?? 'This authenticator does not support the WebAuthn PRF extension');
    }
}
/**
 * Full registration flow: generate nsec, create passkey, encrypt, build event.
 *
 * This is the "setup" flow for a new user or adding a new passkey.
 * Uses the PRF strategy by default — a single passkey, key derived by the
 * authenticator (never in user.id).
 */
export async function setupKeytr(options) {
    const strategy = options.strategy ?? prfStrategy;
    if (!options.strategy)
        await _assertPrfSupported();
    const nsecBytes = _generateNsec();
    const npub = _nsecToNpub(nsecBytes);
    const pubkey = _nsecToHexPubkey(nsecBytes);
    const { credential, keyMaterial } = await strategy.register({ ...options, pubkey });
    try {
        const encryptedBlob = _encryptNsec({
            nsecBytes,
            keyMaterial,
            credentialId: credential.credentialId,
            version: strategy.version,
        });
        const eventTemplate = _buildEvent({
            credential,
            encryptedBlob,
            clientName: options.clientName,
            version: strategy.version,
        });
        return { credential, encryptedBlob, eventTemplate, nsecBytes, npub };
    }
    finally {
        safeZero(keyMaterial);
    }
}
/**
 * Register a backup passkey on an additional gateway for an existing nsec.
 *
 * Call this separately from setupKeytr() — each call triggers one biometric
 * prompt. The user decides when (or if) to add backup gateways.
 */
export async function addBackupGateway(nsecBytes, options) {
    const strategy = options.strategy ?? prfStrategy;
    if (!options.strategy)
        await _assertPrfSupported();
    const pubkey = _nsecToHexPubkey(nsecBytes);
    const { credential, keyMaterial } = await strategy.register({ ...options, pubkey });
    try {
        const encryptedBlob = _encryptNsec({
            nsecBytes,
            keyMaterial,
            credentialId: credential.credentialId,
            version: strategy.version,
        });
        const eventTemplate = _buildEvent({
            credential,
            encryptedBlob,
            clientName: options.clientName,
            version: strategy.version,
        });
        return { credential, encryptedBlob, eventTemplate };
    }
    finally {
        safeZero(keyMaterial);
    }
}
/**
 * Full login flow: try each event's passkey until one succeeds.
 *
 * Pass all kind:31777 events for this user. Each event is dispatched by its
 * `v` tag: v=1 authenticates with PRF, v=3 with the legacy KiH path. The first
 * passkey the authenticator recognises wins. Pass an explicit `strategy` to
 * override dispatch with a custom strategy.
 */
export async function loginWithKeytr(events, strategy) {
    if (events.length === 0) {
        throw new WebAuthnError('No keytr events provided');
    }
    let lastError;
    for (const event of events) {
        // Typed recovery (v4) and npk1 records are opt-in; do not parse their coordinates as an nsec ID.
        if (event.tags.some(tag => tag[0] === 'v' && (tag[1] === '4' || tag[1] === 'npk1')))
            continue;
        const parsed = _parseEvent(event);
        // Choose the authenticate function by event version (or a custom override).
        let authenticate;
        if (strategy) {
            authenticate = strategy.authenticate;
        }
        else if (parsed.version === KEYTR_VERSION) {
            authenticate = authenticatePasskey;
        }
        else if (parsed.version === KEYTR_KIH_VERSION) {
            authenticate = kihAuthenticatePasskey;
        }
        else {
            lastError = new KeytrError(`Unsupported keytr event version ${parsed.version}`);
            continue;
        }
        let keyMaterial;
        try {
            keyMaterial = await authenticate({
                credentialId: parsed.credentialId,
                rpId: parsed.rpId,
                transports: parsed.transports,
            });
        }
        catch (err) {
            lastError = err;
            continue;
        }
        try {
            const nsecBytes = _decryptNsec({
                encryptedBlob: parsed.encryptedBlob,
                keyMaterial,
                credentialId: parsed.credentialId,
                version: parsed.version,
            });
            const npub = _nsecToNpub(nsecBytes);
            return { nsecBytes, npub };
        }
        finally {
            safeZero(keyMaterial);
        }
    }
    throw new WebAuthnError(`No matching passkey found across ${events.length} event(s): ${lastError?.message ?? 'unknown error'}`);
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
export async function setup(options) {
    const strategy = options.strategy ?? prfStrategy;
    if (!options.strategy)
        await _assertPrfSupported();
    const nsecBytes = _generateNsec();
    const npub = _nsecToNpub(nsecBytes);
    const pubkey = _nsecToHexPubkey(nsecBytes);
    const { credential, keyMaterial } = await strategy.register({
        rpId: options.rpId,
        rpName: options.rpName,
        userName: options.userName,
        userDisplayName: options.userDisplayName,
        pubkey,
        timeout: options.timeout,
        hints: options.hints,
    });
    try {
        const encryptedBlob = _encryptNsec({
            nsecBytes,
            keyMaterial,
            credentialId: credential.credentialId,
            version: strategy.version,
        });
        const eventTemplate = _buildEvent({
            credential,
            encryptedBlob,
            clientName: options.clientName,
            version: strategy.version,
        });
        return { credential, encryptedBlob, eventTemplate, nsecBytes, npub };
    }
    finally {
        safeZero(keyMaterial);
    }
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
export async function discover(relays, options) {
    const strategy = options?.strategy ?? prfStrategy;
    const discoverOpts = { rpId: options?.rpId ?? DEFAULT_RP_ID };
    if (options?.timeout)
        discoverOpts.timeout = options.timeout;
    if (options?.mediation)
        discoverOpts.mediation = options.mediation;
    if (options?.hints?.length)
        discoverOpts.hints = options.hints;
    const result = await strategy.discover(discoverOpts);
    const credentialIdB64 = base64url.encode(result.credentialId);
    // PRF returns a pubkey — fetch events by author then match the credential.
    // Legacy KiH returns no pubkey — fetch directly by d-tag.
    let event;
    if (result.pubkey) {
        const events = await _fetchByPubkey(result.pubkey, relays, options?.relayOptions);
        event = events.find(e => e.tags.some(t => t[0] === 'd' && t[1] === credentialIdB64)) ?? null;
    }
    else {
        event = await _fetchByDTag(credentialIdB64, relays, options?.relayOptions);
    }
    if (!event) {
        safeZero(result.keyMaterial);
        throw new KeytrError(`No event matches credential ${credentialIdB64}`);
    }
    try {
        const parsed = _parseEvent(event);
        // Only the shipped PRF (1) and legacy KiH (3) versions are recognised by
        // the built-in strategies. A custom strategy may use its own version.
        if (!options?.strategy && parsed.version !== KEYTR_VERSION && parsed.version !== KEYTR_KIH_VERSION) {
            throw new KeytrError(`Unsupported keytr event version ${parsed.version}`);
        }
        const nsecBytes = _decryptNsec({
            encryptedBlob: parsed.encryptedBlob,
            keyMaterial: result.keyMaterial,
            credentialId: result.credentialId,
            version: parsed.version,
        });
        const pubkey = _nsecToHexPubkey(nsecBytes);
        const npub = _nsecToNpub(nsecBytes);
        // Verify pubkey matches event author (integrity check; also guards the
        // d-tag path against cross-author d-tag collisions).
        if ('pubkey' in event && event.pubkey && event.pubkey !== pubkey) {
            safeZero(nsecBytes);
            throw new KeytrError('Decrypted nsec does not match event author pubkey — possible tampering');
        }
        return { nsecBytes, npub, pubkey };
    }
    finally {
        safeZero(result.keyMaterial);
    }
}
// Draft typed PRF recovery: explicit APIs leave the existing nsec flows unchanged.
export { encryptPayload, decryptPayload, PAYLOAD_VERSION, MAX_PAYLOAD_BYTES } from './crypto/payload.js';
export { buildPayloadEvent, parsePayloadEvent, verifyPayloadEvent, payloadDTag } from './nostr/payload.js';
export { setupPayload, unlockPayload, discoverPayload } from './payload.js';
// Passkey-held Nostr keys (npk1 stored records, tagged handles): opt-in APIs next to v1.
export { classifyHandle } from './webauthn/handle.js';
export { NPK_STORE_PRF_INPUT } from './crypto/npk.js';
export { npkSecretKeys } from './crypto/npk-secret.js';
export { setupStored, discoverStored, decryptStoredSecret } from './stored.js';
//# sourceMappingURL=index.js.map