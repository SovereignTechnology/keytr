/**
 * Stored-mode passkeys from the passkey-held Nostr keys proposal (npk1).
 * Opt-in next to setup()/discover(), which are unchanged. keytr implements
 * stored mode only and never derives a Nostr key from a PRF output.
 */
import { finalizeEvent } from 'nostr-tools/pure';
import { base64url } from '@scure/base';
import { DEFAULT_RP_ID, KEYTR_VERSION, PRF_SALT } from './types.js';
import { KeytrError, PasskeyModeError } from './errors.js';
import { registerStoredPasskey } from './webauthn/register.js';
import { authenticatePrf, discoverStoredPasskey } from './webauthn/authenticate.js';
import { classifyHandle } from './webauthn/handle.js';
import { decryptNpkRecord, encryptNpkRecord, NPK_STORE_PRF_INPUT } from './crypto/npk.js';
import { decodeNpkSecret, encodeNpkSecret, npkSecretKeys } from './crypto/npk-secret.js';
import { decryptNsec } from './crypto/decrypt.js';
import { safeZero } from './crypto/builtins.js';
import { buildNpkEvent, verifyNpkEvent, eligibleNpkEvent } from './nostr/npk.js';
import { parseKeytrEvent } from './nostr/event.js';
import { nsecToHexPubkey } from './nostr/keys.js';
import { fetchKeytrEvents, fetchStoredEvents } from './nostr/relay.js';
/** Throw unless `author` is one of the secret's importable keys. */
function assertAuthor(secret, author) {
    const keys = npkSecretKeys(secret);
    keys.forEach(k => safeZero(k.secretKey));
    if (!keys.some(k => k.pubkey === author))
        throw new KeytrError('Record author is not one of the stored secret\'s keys');
}
/**
 * Decrypt an npk1 record (from relays, a file or a `largeBlob`) with the PRF
 * output for NPK_STORE_PRF_INPUT, and check that the author is one of the
 * secret's keys (for a seed, its main account) before returning it.
 */
export function decryptStoredSecret(options) {
    const { type, plaintext } = decryptNpkRecord(options);
    try {
        const secret = decodeNpkSecret(type, plaintext);
        try {
            assertAuthor(secret, options.author);
        }
        catch (err) {
            if (secret.type === 'key')
                safeZero(secret.secretKey);
            throw err;
        }
        return secret;
    }
    finally {
        safeZero(plaintext);
    }
}
/**
 * Register a tagged stored passkey for `secret`, encrypt it as an npk1 record
 * and sign the relay event with the author's key. The author is the key, a
 * seed's main account, or the vault's `default` account (else its first
 * importable one). The secret is checked before the passkey prompt; nothing
 * is published.
 */
export async function setupStored(secret, options) {
    if (secret.type === 'seed')
        secret = { type: 'vault', vault: { seed: secret.seed, accounts: [{ kind: 'derived', path: "m/44'/1237'/0'/0/0" }] } };
    const plaintext = encodeNpkSecret(secret); // validates and checks the size before the prompt
    const keys = npkSecretKeys(secret);
    const chosen = keys.find(k => k.default) ?? keys[0];
    keys.forEach(k => k !== chosen && safeZero(k.secretKey));
    try {
        if (!chosen)
            throw new KeytrError('The vault has no importable account to use as author');
        const author = chosen.pubkey;
        const { credential, keyMaterial } = await registerStoredPasskey({ ...options, author });
        try {
            const context = { rpId: credential.rpId, author, credentialId: credential.credentialId };
            const record = encryptNpkRecord({ ...context, type: secret.type, plaintext, keyMaterial });
            const event = finalizeEvent(buildNpkEvent({ ...context, record }), chosen.secretKey);
            return { credential, author, record, event };
        }
        finally {
            safeZero(keyMaterial);
        }
    }
    finally {
        safeZero(plaintext);
        if (chosen)
            safeZero(chosen.secretKey);
    }
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
export async function discoverStored(relays, options = {}) {
    const rpId = options.rpId ?? DEFAULT_RP_ID;
    const { credentialId, userHandle, prfOutput } = await discoverStoredPasskey({ ...options, rpId });
    const auth = { credentialId, rpId, timeout: options.timeout };
    try {
        const handle = classifyHandle(userHandle);
        if (handle.mode === 'derived')
            throw new PasskeyModeError('derived', `parameter set ${handle.parameterSet}`);
        if (handle.mode === 'unsupported')
            throw new PasskeyModeError('unsupported');
        if (handle.mode === 'unknown')
            throw new PasskeyModeError('unknown');
        if (handle.legacy === 'key-in-handle')
            throw new PasskeyModeError('unsupported', 'legacy key-in-handle passkey: use discover() and migrateFromKih()');
        const { author } = handle;
        const events = handle.legacy === 'raw-pubkey'
            ? await fetchKeytrEvents(author, relays, options.relayOptions)
            : await fetchStoredEvents(author, credentialId, relays, options.relayOptions);
        if (handle.legacy === 'raw-pubkey') {
            const d = base64url.encode(credentialId);
            const v1 = events.find(e => e.tags.some(t => t[0] === 'd' && t[1] === d) && e.tags.some(t => t[0] === 'v' && t[1] === String(KEYTR_VERSION)));
            if (!v1)
                throw new PasskeyModeError('unknown', '32-byte handle with no keytr v1 record; a v4 payload opens with discoverPayload()');
            const keyMaterial = await authenticatePrf(auth, PRF_SALT);
            try {
                const secretKey = decryptNsec({ encryptedBlob: parseKeytrEvent(v1).encryptedBlob, keyMaterial, credentialId });
                if (nsecToHexPubkey(secretKey) !== author) {
                    safeZero(secretKey);
                    throw new KeytrError('Decrypted nsec does not match event author pubkey - possible tampering');
                }
                return { format: 'keytr-v1', secret: { type: 'key', secretKey }, author, credentialId };
            }
            finally {
                safeZero(keyMaterial);
            }
        }
        // Select signed vault coordinates before decoding; a malformed latest vault must not roll back.
        const eligible = events.flatMap(event => {
            try {
                return [{ event, type: eligibleNpkEvent(event, { author, rpId, credentialId }) }];
            }
            catch {
                return [];
            }
        }).sort((a, b) => b.event.created_at - a.event.created_at || a.event.id.localeCompare(b.event.id));
        const newestVault = eligible.find(e => e.type === 'vault');
        const candidates = [...(newestVault ? [newestVault] : []), ...eligible.filter(e => e.type !== 'vault')];
        if (!candidates.length)
            throw new PasskeyModeError('record-not-found', `credential ${base64url.encode(credentialId)}`);
        const keyMaterial = prfOutput?.slice() ?? await authenticatePrf(auth, NPK_STORE_PRF_INPUT);
        try {
            let failure;
            const warnings = [];
            for (const { event } of candidates) {
                try {
                    const { record } = verifyNpkEvent(event, { author, rpId, credentialId });
                    return { format: 'npk1', secret: decryptStoredSecret({ record, keyMaterial, rpId, author, credentialId }), author, credentialId, warnings };
                }
                catch (err) {
                    failure = err;
                    warnings.push('A recovery copy could not be opened; check for possible tampering.');
                }
            }
            throw failure;
        }
        finally {
            safeZero(keyMaterial);
        }
    }
    finally {
        if (prfOutput)
            safeZero(prfOutput);
    }
}
//# sourceMappingURL=stored.js.map