import { base64url } from '@scure/base';
import { verifyEvent } from 'nostr-tools/pure';
import { KEYTR_EVENT_KIND } from '../types.js';
import { KeytrError } from '../errors.js';
import { PAYLOAD_VERSION, decodePayloadBlob, validatePayloadContext } from '../crypto/payload.js';
/** Separate coordinates keep a vault from replacing the same credential's nsec. */
export function payloadDTag(context) {
    return `${base64url.encode(context.credentialId)}:${context.payloadType}:${context.schema}`;
}
export function buildPayloadEvent(options) {
    const context = { ...options, credentialId: options.credential.credentialId, rpId: options.credential.rpId };
    validatePayloadContext(context);
    decodePayloadBlob(options.encryptedBlob);
    const tags = [
        ['d', payloadDTag(context)], ['credential', base64url.encode(context.credentialId)],
        ['rp', context.rpId], ['algo', 'aes-256-gcm'], ['kdf', 'hkdf-sha256'],
        ['v', String(PAYLOAD_VERSION)], ['type', context.payloadType], ['schema', context.schema],
    ];
    if (options.clientName)
        tags.push(['client', options.clientName]);
    return { kind: KEYTR_EVENT_KIND, content: options.encryptedBlob, tags, created_at: Math.floor(Date.now() / 1000) };
}
/** Parse public metadata; this does not authenticate an unsigned template. */
export function parsePayloadEvent(event) {
    if (event.kind !== KEYTR_EVENT_KIND || !Array.isArray(event.tags) || event.tags.length > 32)
        throw new KeytrError('Invalid payload event');
    const tag = (name) => {
        const tags = event.tags.filter(t => Array.isArray(t) && t[0] === name);
        if (tags.length !== 1 || tags[0].length !== 2 || typeof tags[0][1] !== 'string' || tags[0][1].length > 2048)
            throw new KeytrError(`Invalid or duplicate ${name} tag`);
        return tags[0][1];
    };
    if (tag('v') !== String(PAYLOAD_VERSION) || tag('algo') !== 'aes-256-gcm' || tag('kdf') !== 'hkdf-sha256')
        throw new KeytrError('Unsupported payload encryption');
    const encodedId = tag('credential');
    let credentialId;
    try {
        credentialId = base64url.decode(encodedId);
    }
    catch {
        throw new KeytrError('Invalid credential ID');
    }
    if (base64url.encode(credentialId) !== encodedId)
        throw new KeytrError('Noncanonical credential ID');
    const context = { credentialId, pubkey: event.pubkey, rpId: tag('rp'), payloadType: tag('type'), schema: tag('schema') };
    validatePayloadContext(context);
    if (tag('d') !== payloadDTag(context))
        throw new KeytrError('Payload coordinate mismatch');
    decodePayloadBlob(event.content);
    return { ...context, encryptedBlob: event.content };
}
/** The expected author/RP/type/schema come from the application or discovered credential. */
export function verifyPayloadEvent(event, expected) {
    const parsed = parsePayloadEvent(event);
    for (const field of ['pubkey', 'rpId', 'payloadType', 'schema']) {
        if (parsed[field] !== expected[field])
            throw new KeytrError(`Unexpected payload ${field}`);
    }
    if (expected.credentialId && base64url.encode(parsed.credentialId) !== base64url.encode(expected.credentialId))
        throw new KeytrError('Unexpected payload credential');
    // Copy only NIP-01 fields so a cached verification symbol cannot bypass signature checks.
    const signed = { id: event.id, sig: event.sig, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags.map(t => [...t]), content: event.content };
    if (!verifyEvent(signed))
        throw new KeytrError('Invalid payload event signature');
    return parsed;
}
//# sourceMappingURL=payload.js.map