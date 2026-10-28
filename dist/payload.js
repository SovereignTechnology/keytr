import { DEFAULT_RP_ID } from './types.js';
import { registerPasskey } from './webauthn/register.js';
import { authenticatePasskey, discoverPasskey } from './webauthn/authenticate.js';
import { fetchKeytrEvents } from './nostr/relay.js';
import { encryptPayload, decryptPayload, validatePayloadContext, MAX_PAYLOAD_BYTES } from './crypto/payload.js';
import { buildPayloadEvent, verifyPayloadEvent, payloadDTag } from './nostr/payload.js';
import { safeZero } from './crypto/builtins.js';
import { KeytrError } from './errors.js';
/** Register PRF and prepare a typed event. The caller signs and publishes with the author key. */
export async function setupPayload(payload, options) {
    validatePayloadContext({ ...options, rpId: options.rpId ?? DEFAULT_RP_ID, credentialId: new Uint8Array([0]) });
    if (!(payload instanceof Uint8Array) || !payload.length || payload.length > MAX_PAYLOAD_BYTES)
        throw new KeytrError('Invalid payload size');
    const { credential, keyMaterial } = await registerPasskey(options);
    try {
        const encryptedBlob = encryptPayload({ ...options, rpId: credential.rpId, credentialId: credential.credentialId, keyMaterial, payload });
        const eventTemplate = buildPayloadEvent({ ...options, credential, encryptedBlob });
        return { credential, encryptedBlob, eventTemplate };
    }
    finally {
        safeZero(keyMaterial);
    }
}
/** Validate the signed event and caller-selected context before starting WebAuthn. */
export async function unlockPayload(event, expected) {
    const context = verifyPayloadEvent(event, expected);
    const keyMaterial = await authenticatePasskey(context);
    try {
        return decryptPayload({ ...context, keyMaterial });
    }
    finally {
        safeZero(keyMaterial);
    }
}
/** Discover by userHandle without asking for an npub. Never silently restore an older snapshot. */
export async function discoverPayload(relays, options) {
    const rpId = options.rpId ?? DEFAULT_RP_ID;
    const credential = await discoverPasskey({ ...options, rpId });
    try {
        if (credential.mode !== 'prf' || !credential.pubkey)
            throw new KeytrError('Payload recovery requires a PRF credential with a public user handle');
        const expected = { ...options, rpId, pubkey: credential.pubkey, credentialId: credential.credentialId };
        const coordinate = payloadDTag(expected);
        const events = await fetchKeytrEvents(credential.pubkey, relays, options.relayOptions);
        const candidates = events.filter(event => event.tags.some(t => t[0] === 'd' && t[1] === coordinate)).sort((a, b) => b.created_at - a.created_at || a.id.localeCompare(b.id));
        const event = candidates[0];
        if (!event)
            throw new KeytrError('No matching recovery payload found');
        const context = verifyPayloadEvent(event, expected);
        return { payload: decryptPayload({ ...context, keyMaterial: credential.keyMaterial }), pubkey: credential.pubkey };
    }
    finally {
        safeZero(credential.keyMaterial);
    }
}
//# sourceMappingURL=payload.js.map